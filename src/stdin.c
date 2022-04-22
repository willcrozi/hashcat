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

#define REQS_IDX_MASK (DEVICES_MAX - 1)

// forward declarations

static void *thread_stdin_read (void *p);
static i32   stdin_read (stdin_ctx_t *stdin_ctx, char *dst, u32 len);
static i32   stdin_os_read (const stdin_ctx_t *stdin_ctx, char *dst, u32 len);

static inline i32 split_tail (const char **restrict end, char *restrict tail_dst);

int stdin_open (stdin_ctx_t *stdin_ctx, hashcat_ctx_t *hashcat_ctx)
{
  // capacity of ring buffer for waiting requests must be a power-of-two (uses unsigned overflow)

  assert (power_of_two_ceil_32 (DEVICES_MAX) == DEVICES_MAX);

  stdin_ctx->reqs_head = 0;
  stdin_ctx->reqs_tail = 0;

  hc_thread_mutex_init (stdin_ctx->mux_request);
  hc_thread_cond_init  (&stdin_ctx->cond_request);

  hc_thread_mutex_init (stdin_ctx->mux_result);

  stdin_ctx->eof  = false;
  stdin_ctx->stop = false;

  stdin_ctx->read_success_cnt = 0;

  stdin_ctx->hashcat_ctx = hashcat_ctx;
  stdin_ctx->status_ctx  = hashcat_ctx->status_ctx;

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

  hc_thread_create (stdin_ctx->read_thread, thread_stdin_read, (void *) stdin_ctx);

  return 0;
}

void stdin_close (stdin_ctx_t *stdin_ctx)
{
  stdin_stop (stdin_ctx);

  hc_thread_cond_close (&stdin_ctx->cond_request);

  hc_thread_mutex_delete (stdin_ctx->mux_request);
  hc_thread_mutex_delete (stdin_ctx->mux_result);

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

void stdin_stop (stdin_ctx_t *stdin_ctx)
{
  hc_thread_mutex_lock (stdin_ctx->mux_request);
  hc_thread_mutex_lock (stdin_ctx->mux_result);

  if (stdin_ctx->stop == false)
  {
    stdin_ctx->eof  = true;
    stdin_ctx->stop = true;

    #if defined (_WIN)
    // TODO possibly only required for windows console IO...
    CancelIoEx (stdin_ctx->hnd, NULL);

    SetEvent (stdin_ctx->read_event);
    #endif

    hc_thread_cond_notify (&stdin_ctx->cond_request);

    while (stdin_ctx->reqs_head != stdin_ctx->reqs_tail)
    {
      stdin_req_t *req = &stdin_ctx->requests[stdin_ctx->reqs_head++ & REQS_IDX_MASK];

      hc_thread_cond_notify (req->result->cond);
    }

    hc_thread_mutex_unlock (stdin_ctx->mux_request);
    hc_thread_mutex_unlock (stdin_ctx->mux_result);
  }
}

void stdin_wait_exit (stdin_ctx_t *stdin_ctx)
{
  // wait for stdin_ctx's read-thread to exit, called by host dispatch/device threads before
  // being able to safely clean up result buffer and wait-condition

  hc_thread_cond_notify (&stdin_ctx->cond_request); // belt-and-braces

  hc_thread_wait (1, &stdin_ctx->read_thread);
}

void stdin_read_request (stdin_ctx_t *stdin_ctx, char *buf, stdin_result_t *result)
{
  // registers a request for (full) lines to be read into buf from stdin with the result
  // to be placed into *result, this operation always succeeds resulting in a valid
  // result object to be used for waiting/cancellation
  //
  // no external locking required when called from multiple threads but any given thread
  // must call stdin_read_wait() between successive calls to this function

  // NOTE: requires that the memory locations buf[-1] and buf[buf_len] are valid and part of
  //       the same array object as the the range buf[0] ... buf[buf_len - 1] (this is for
  //       prepending/appending '\n' sentinel bytes immediately before and after the buffer

  hc_thread_mutex_lock (stdin_ctx->mux_request);

  stdin_req_t *req = &stdin_ctx->requests[stdin_ctx->reqs_tail++ & REQS_IDX_MASK];

  result->buf = NULL;
  result->cnt = 0;

  req->buf    = buf;
  req->result = result;

  hc_thread_mutex_unlock (stdin_ctx->mux_request);

  hc_thread_cond_notify (&stdin_ctx->cond_request);
}

void stdin_read_wait (stdin_ctx_t *stdin_ctx, stdin_result_t *result)
{
  // blocks until the request specified by req has completed or failed, the first
  // line begins at result->buf and the total byte-length of data indicated by
  // result->cnt, result->cnt == -1 indicates io-error/eof and that no data was
  // written to result->buf
  //
  // the final line (before eof) is guaranteed to have a trailing '\n' even if the
  // input did not

  hc_thread_mutex_lock (stdin_ctx->mux_result);

  while (result->buf == NULL)
  {
    if (stdin_ctx->eof == false)
    {
      hc_thread_cond_wait (result->cond, stdin_ctx->mux_result);
    }
    else
    {
      result->cnt = RESULT_EOF;

      break;
    }
  }

  hc_thread_mutex_unlock (stdin_ctx->mux_result);
}

// stdin reader thread

static void *thread_stdin_read (void *p)
{
  stdin_ctx_t  *stdin_ctx  = (stdin_ctx_t *) p;
  status_ctx_t *status_ctx = stdin_ctx->status_ctx;

  bool eof  = false;
  bool done = false;

  #define PARTIAL_BUF_SZ (PW_MAX + sizeof (char16)) // allow vector overrun on read/write

  char partial[PARTIAL_BUF_SZ]; // partial line carried over from previous request
  i32  partial_len = 0;         // length of partial line, value of -1 indicates skipping over-length line

  char *restrict dest     = NULL; // write cursor for current request
  char *restrict dest_lim = NULL; // write limit for cursor

  stdin_req_t req = (stdin_req_t) { .buf = NULL, .result = NULL };

  while (done == false)
  {
    if (status_ctx->run_thread_level1 == false) break; // completion/abort

    // get next request

    hc_thread_mutex_lock (stdin_ctx->mux_request);

    while (stdin_ctx->reqs_head == stdin_ctx->reqs_tail)
    {
      if (status_ctx->run_thread_level1 == true)
      {
        hc_thread_cond_wait (&stdin_ctx->cond_request, stdin_ctx->mux_request);
      }
      else
      {
        hc_thread_mutex_unlock (stdin_ctx->mux_request);

        goto exit;
      }
    }

    req = stdin_ctx->requests[stdin_ctx->reqs_head++ & REQS_IDX_MASK];

    hc_thread_mutex_unlock (stdin_ctx->mux_request);

    dest     = req.buf;
    dest_lim = dest + STDIN_BUF_SZ;

    if (partial_len > 0)
    {
      buf_cpy (dest, &partial[0], partial_len);

      dest += partial_len;
    }

    // read in data

    if (eof == false)
    {
      while (dest < dest_lim)
      {
        u32 read_len = dest_lim - dest;

        // assert (read_len <= STDIN_BUF_SZ);

        i32 read_cnt = stdin_read (stdin_ctx, dest, read_len);

        if (read_cnt > 0)
        {
          dest += read_cnt;
        }
        else
        {
          if (read_cnt == 0)
          {
            // timeout TODO timeout-flush

            if (status_ctx->run_thread_level1 == true) continue;
          }

          eof = true;

          break;
        }
      }
    }

    *dest = '\n'; // sentinel

    // perform skip if needed

    if (partial_len == -1)
    {
      while (*req.buf++ != '\n');

      if (req.buf < dest) partial_len = 0; // newline was found, password rejected
    }

    // prepare result, splitting and storing any trailing partial line bytes

    partial_len = split_tail ((const char **) &dest, &partial[0]);

    // set result and notify waiting device thread

    stdin_result_t *result = req.result;

    i32 cnt = (i32) (dest - req.buf);

    hc_thread_mutex_lock (stdin_ctx->mux_result);

    result->buf = req.buf;
    result->cnt = cnt;

    stdin_ctx->eof = done;

    hc_thread_cond_notify (result->cond);

    hc_thread_mutex_unlock (stdin_ctx->mux_result);

    done = (eof == true) & (partial_len == 0);
  }

  exit:

  stdin_stop (stdin_ctx);

  return NULL;
}

// helpers

static i32 stdin_read (stdin_ctx_t *stdin_ctx, char *dst, u32 len)
{
  // returns count of bytes read, or -1 if eof/error

  i32 read_cnt = stdin_os_read (stdin_ctx, dst, len);

  status_ctx_t *status_ctx = stdin_ctx->status_ctx;

  if (read_cnt > 0)
  {
    status_ctx->stdin_read_timeout_cnt = 0;

    stdin_ctx->read_success_cnt++;

    #define DISABLE_TIMEOUT_ABORT_AFTER 1000

    if (stdin_ctx->read_success_cnt == DISABLE_TIMEOUT_ABORT_AFTER)
    {
      user_options_t *user_options = stdin_ctx->hashcat_ctx->user_options;

      user_options->stdin_timeout_abort = 0;
    }
  }
  else if (read_cnt == 0)
  {
    // timeout

    status_ctx->stdin_read_timeout_cnt += 1;
  }

  return read_cnt;
}

#if defined (_WIN)
static i32 stdin_os_read (const stdin_ctx_t *stdin_ctx, char *dst, u32 len)
{
  DWORD read_cnt = 0;

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

  return (i32) read_cnt;
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

static inline i32 split_tail (const char **restrict end, char *restrict tail_dst)
{
  // scans backwards from (*end - 1) and updates *end to point to character after
  // the trailing newline (or prepended sentinel '\n' char)
  //
  // if the count of trailing bytes <= PW_MAX then the bytes are copied to tail_dst and the copy
  // count is returned, otherwise no bytes are copied and -1 is returned
  //
  // must be used with a sentinel '\n' at the front of the array-object pointed to by *end - 1

  const char *restrict trim = *end;

  while (*(--trim) != '\n') {}; // relies on prepended sentinel '\n'

  trim++;

  i32 tail_len = (i32) (*end - trim);

  *end = trim;

  if (tail_len <= PW_MAX)
  {
    buf_cpy (tail_dst, trim, tail_len);

    return tail_len;
  }
  else
  {
    return -1;
  }

}
