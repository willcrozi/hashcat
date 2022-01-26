/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STDIN_H
#define _STDIN_H

#define STDIN_BUF_SZ       (48 * 1024)
#define STDIN_BLK_SZ       (sizeof (char16))
#define STDIN_BUF_ALLOC_SZ (STDIN_BLK_SZ + STDIN_BUF_SZ + STDIN_BLK_SZ) // allow for alignment, sentinels, and vector overrun

#define PARTIAL_BUF_SZ     (PW_MAX + STDIN_BLK_SZ) // allow for vector overrun

typedef struct stdin_ctx
{
  char partial[PARTIAL_BUF_SZ]; // partial line carried over from previous buffer
  i32  partial_len;             // length of partial data, -1 if length > PW_MAX and need to skip to next line

  bool eof;

  // device thread read queue (ring buffer)

  hc_thread_mutex_t mux_read;
  hc_thread_cond_t *waiting[DEVICES_MAX];

  u8 wait_head;
  u8 wait_tail;

  #if defined (_WIN)
  HANDLE hnd;
  HANDLE read_event;

  bool is_console;
  #endif

  hashcat_ctx_t *hashcat_ctx;

  u32  read_success_cnt;

} stdin_ctx_t;

typedef struct stdin_result
{
  char *start;
  i32   cnt;

} stdin_result_t;

int   stdin_open (stdin_ctx_t *stdin_ctx, hashcat_ctx_t *hashcat_ctx);
void  stdin_close (stdin_ctx_t *stdin_ctx);

stdin_result_t stdin_read (stdin_ctx_t *stdin_ctx, char *restrict buf, hc_thread_cond_t *cond);

#endif // _STDIN_H