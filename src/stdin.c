/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (_WIN)
#include <windows.h>
#else
#include <fcntl.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "stdin.h"

#define STDIN_BUF_SZ       (HCBUFSIZ_LARGE)
#define STDIN_BUF_ALLOC_SZ (STDIN_BUF_SZ + sizeof (char16)) // allow for sentinel and vector overrun

#define READ_TIMEOUT_SEC 1

int stdin_open (stdin_ctx_t *stdin_ctx)
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
  // use POSIX non-blocking reads

  int flags = fcntl (STDIN_FILENO, F_GETFL, 0);

  if (flags == -1) return -1;

  if (fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK)) return -1;

  #endif

  char *buf = (char *) hcmalloc (STDIN_BUF_ALLOC_SZ);

  if (buf == NULL) return -1;

  stdin_ctx->buf       = buf;
  stdin_ctx->head      = buf;
  stdin_ctx->check     = buf;
  stdin_ctx->tail      = buf;
  stdin_ctx->prev      = '\0';
  stdin_ctx->eof       = false;

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
  #endif

  hcfree (stdin_ctx->buf);

  stdin_ctx->buf = NULL;
}

#if defined (_WIN)
static i32 stdin_os_read (stdin_ctx_t *stdin_ctx, char *dst, u32 len)
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
static i32 stdin_os_read (stdin_ctx_t *stdin_ctx, char *dst, u32 len)
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

int stdin_read (stdin_ctx_t *stdin_ctx)
{
  u32 read_len = (stdin_ctx->buf + STDIN_BUF_SZ) - stdin_ctx->tail;

  if (read_len == 0)
  {
    // reset buffer

    u32 copy_len = (u32) (stdin_ctx->tail - stdin_ctx->head);

    u32 check_off = (u32) (stdin_ctx->check - stdin_ctx->head);

    if (copy_len > 0)
    {
      if (copy_len < (STDIN_BUF_SZ / 2))
      {
        buf_cpy (stdin_ctx->buf, stdin_ctx->head, copy_len);
      }
      else
      {
        memmove (stdin_ctx->buf, stdin_ctx->head, copy_len);
      }
    }

    stdin_ctx->head  = stdin_ctx->buf;
    stdin_ctx->check = stdin_ctx->buf + check_off;
    stdin_ctx->tail  = stdin_ctx->buf + copy_len;

    read_len = STDIN_BUF_SZ - copy_len;
  }

  i32 read_cnt = stdin_os_read (stdin_ctx, stdin_ctx->tail, read_len);

  stdin_ctx->tail += read_cnt;

  *stdin_ctx->tail = '\n'; // sentinel

  return (int) read_cnt;
}

char *stdin_next_line (stdin_ctx_t *stdin_ctx, size_t *line_len)
{
  char prev = stdin_ctx->prev;

  const char *head  = stdin_ctx->head;
  const char *check = stdin_ctx->check;
  const char *tail  = stdin_ctx->tail;

  while (*check != '\n') prev = *check++;

  if (check == tail)
  {
    // no newline found

    stdin_ctx->check = (char *) check;
    stdin_ctx->prev  = prev;

    return NULL;
  }

  *line_len = (size_t) (check - head);

  if (prev == '\r') (*line_len)--;

  stdin_ctx->prev = '\0';

  stdin_ctx->check = (char *) check + 1;
  stdin_ctx->head  = stdin_ctx->check;

  return (char *) head;
}
