/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (_WIN)
#include <windows.h>
#else
#include <fcntl.h>
#endif

#include <assert.h>

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "thread.h"
#include "stdin.h"

#define READ_TIMEOUT_SEC 1

int stdin_open (stdin_ctx_t *stdin_ctx, hashcat_ctx_t *hashcat_ctx)
{
  #if defined (_WIN)
  stdin_ctx->hnd = GetStdHandle (STD_INPUT_HANDLE);

  if (stdin_ctx->hnd == NULL) return -1;

  DWORD mode;

  stdin_ctx->is_console = (GetConsoleMode (stdin_ctx->hnd, &mode) == 1);

  if (stdin_ctx->is_console == false)
  {
    // pipe mode

    if (SetNamedPipeHandleState (stdin_ctx->hnd, PIPE_READMODE_BYTE | PIPE_WAIT, NULL, NULL) == 0) return -1;

    // use auto-reset event to wait on reads

    stdin_ctx->read_event = CreateEvent (NULL, FALSE, FALSE, NULL);

    if (stdin_ctx->read_event == NULL) return -1;
  }
  else
  {
    stdin_ctx->read_event = NULL;
  }

  #else
  // use POSIX non-blocking I/O

  int flags = fcntl (STDIN_FILENO, F_GETFL, 0);

  if (flags == -1) return -1;

  if (fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK)) return -1;

  #endif

  stdin_ctx->partial_len = 0;

  stdin_ctx->eof  = false;

  // the ring buffer for wait-conditions uses unsigned integer overflow and so its capacity, DEVICES_MAX,
  // must be a power-of-two

  assert (power_of_two_ceil_32 (DEVICES_MAX) == DEVICES_MAX);

  hc_thread_mutex_init (stdin_ctx->mux_read);

  stdin_ctx->wait_head = 0;
  stdin_ctx->wait_tail = 0;

  stdin_ctx->hashcat_ctx = hashcat_ctx;

  stdin_ctx->read_success_cnt = 0;

  return 0;
}

void stdin_close (stdin_ctx_t *stdin_ctx)
{
  #if defined (_WIN)
  if (stdin_ctx->read_event != NULL)
  {
    CloseHandle (stdin_ctx->read_event);

    stdin_ctx->read_event = NULL;
  }

  CloseHandle (stdin_ctx->hnd);

  stdin_ctx->hnd = NULL;
  #else
  (void) *stdin_ctx; // no-op (avoids warning)
  #endif
}

#if defined (_WIN)
static i32 stdin_os_read (const stdin_ctx_t *stdin_ctx, char *dst, u32 len)
{
  i32 read_cnt = 0;

  if (stdin_ctx->is_console == false)
  {
    // pipe mode

    OVERLAPPED olap = { 0 };

    olap.hEvent = stdin_ctx->read_event;

    if (ReadFile (stdin_ctx->hnd, dst, len, (LPDWORD) &read_cnt, &olap) != 0)
    {
      return (i32) read_cnt;
    }

    if (GetLastError () != ERROR_IO_PENDING) return -1; // eof/error

    // async read in progress

    DWORD waitResult = WaitForSingleObject (stdin_ctx->read_event, (READ_TIMEOUT_SEC * 1000));

    if (waitResult == WAIT_ABANDONED || waitResult == WAIT_FAILED) return -1; // error

    if (GetOverlappedResult (stdin_ctx->hnd, &olap, (LPDWORD) &read_cnt, FALSE) == 0)
    {
      if (GetLastError () != ERROR_IO_INCOMPLETE) return -1; // eof/error

      // timeout, cancel the read-op and wait for its conclusion

      if (CancelIo (stdin_ctx->hnd) == 0) return -1;

      while (GetOverlappedResult (stdin_ctx->hnd, &olap, (LPDWORD) &read_cnt, FALSE) == 0)
      {
        switch (GetLastError ())
        {
          case ERROR_IO_INCOMPLETE:       continue;
          case ERROR_OPERATION_ABORTED:   return  0; // timeout
          default:                        return -1; // eof/error
        }
      }
    }
  }
  else
  {
    // console mode

    int rc = select_read_timeout_console (READ_TIMEOUT_SEC);

    if (rc == 0) return 0; // timeout

    if (rc < 0) return -1; // eof/error

    if (ReadFile (stdin_ctx->hnd, dst, len, (LPDWORD) &read_cnt, NULL) == 0)
    {
      return -1; // eof/error
    }
  }

  return read_cnt;
}

#else
static i32 stdin_os_read (const stdin_ctx_t *stdin_ctx, char *dst, u32 len)
{
  (void) *stdin_ctx; // unused here on POSIX

  ssize_t read_cnt = read (STDIN_FILENO, dst, len); // avoid select() if possible

  if (read_cnt > 0) return (i32) read_cnt;

  if (read_cnt < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
  {
    int rc = select_read_timeout (STDIN_FILENO, READ_TIMEOUT_SEC);

    if (rc > 0)
    {
      read_cnt = read (STDIN_FILENO, dst, len);
    }
    else
    {
      if (rc == 0) return 0; // timeout
    }
  }

  if (read_cnt > 0) return (i32) read_cnt;

  return -1; // eof/error
}

#endif

stdin_result_t stdin_read (stdin_ctx_t *stdin_ctx, char *restrict buf, hc_thread_cond_t *cond)
{
  // reads full lines into buf from stdin, returning a result object with pointer to first
  // line and byte length of data, the final line (before eof) is guaranteed to have a
  // trailing '\n' even if the input did not
  //
  // result.cnt == -1 indicates eof (no data copied to buf and result.start is undefined)

  // NOTE: requires that the memory locations &buf[-1] and &buf[buf_len] are valid and part of
  //       the same array object as the the range buf[0] ... buf[buf_len - 1] (this is for
  //       prepending/appending '\n' sentinel bytes immediately before the buffer and after
  //       the data

  status_ctx_t   *status_ctx   = stdin_ctx->hashcat_ctx->status_ctx;
  user_options_t *user_options = stdin_ctx->hashcat_ctx->user_options;

  stdin_result_t result;

  char *dst   = buf;
  char *limit = buf + STDIN_BUF_SZ;

  #define WAIT_MASK (DEVICES_MAX - 1)

  // acquire the read 'lock', queueing if necessary

  hc_thread_mutex_lock (stdin_ctx->mux_read);

  u8 wait_pos = stdin_ctx->wait_tail++;

  // assert ((stdin_ctx->wait_tail - stdin_ctx->wait_head) < DEVICES_MAX); // waiter ring-buffer range check

  stdin_ctx->waiting[wait_pos & WAIT_MASK] = cond;

  while (stdin_ctx->wait_head != wait_pos)
  {
    hc_thread_cond_wait (cond, stdin_ctx->mux_read);
  }

  // start of 'locked' section (only a single device thread executes here)

  bool eof = stdin_ctx->eof;

  hc_thread_mutex_unlock (stdin_ctx->mux_read);

  // prepend previous partial line data if present

  if (stdin_ctx->partial_len > 0)
  {
    buf_cpy (dst, &stdin_ctx->partial[0], stdin_ctx->partial_len);

    dst += stdin_ctx->partial_len;

    stdin_ctx->partial_len = 0;
  }

  // read data from stdin

  if (eof == false)
  {
    while (dst < limit)
    {
      if (status_ctx->run_thread_level1 == false) break;

      u32 read_len = limit - dst;

      i32 read_cnt = stdin_os_read (stdin_ctx, dst, read_len);

      if (read_cnt > 0)
      {
        status_ctx->stdin_read_timeout_cnt = 0;

        if (user_options->stdin_timeout_abort > 0)
        {
          #define DISABLE_READ_TIMEOUT_AFTER 1000

          stdin_ctx->read_success_cnt++;

          if (stdin_ctx->read_success_cnt == DISABLE_READ_TIMEOUT_AFTER) user_options->stdin_timeout_abort = 0;
        }

        dst += read_cnt;
      }
      else
      {
        eof = read_cnt < 0;

        if (eof == true) break;

        status_ctx->stdin_read_timeout_cnt++; // timeout (TODO: flushing)
      }
    }
  }
  else
  {
    // eof and no partial data

    result.cnt = -1;

    goto release_exit;
  }

  *dst = '\n'; // sentinel

  // skip to next line if previous partial length exceeded PW_MAX

  if (stdin_ctx->partial_len == -1)
  {
    while (*buf++ != '\n') {}

    // TODO instead of returning empty result below we could jump back to read section
    //      above (would require another label and goto)

    if (buf > dst) buf = dst; // sentinel hit (no newline), return empty result
  }

  // trim and store trailing partial line bytes

  const char *dst_prev = dst;

  while (*--dst != '\n') {}

  dst++;

  i32 trim_cnt = (i32) (dst_prev - dst);

  stdin_ctx->partial_len = (trim_cnt <= PW_MAX) ? trim_cnt : -1;

  if (stdin_ctx->partial_len > 0)
  {
    buf_cpy (&stdin_ctx->partial[0], dst, trim_cnt);
  }

  result = (stdin_result_t) { .start = buf, .cnt = (i32) (dst - buf) };

  // end of 'locked' section

  release_exit:

  hc_thread_mutex_lock (stdin_ctx->mux_read);

  // check that either output data has trailing/sentinel newline, or eof is signalled

  // assert (*(buf + (result.cnt - 1)) == '\n' || *(buf + result.cnt) == '\n' || (result.cnt == -1));

  stdin_ctx->eof = eof;

  // notify next waiting device thread

  stdin_ctx->wait_head++;

  if (stdin_ctx->wait_head != stdin_ctx->wait_tail)
  {
    hc_thread_cond_t *waiter_nxt = stdin_ctx->waiting[stdin_ctx->wait_head & WAIT_MASK];

    hc_thread_cond_notify (waiter_nxt);
  }

  hc_thread_mutex_unlock (stdin_ctx->mux_read);

  return result;
}
