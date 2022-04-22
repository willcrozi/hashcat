/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STDIN_H
#define _STDIN_H

#define STDIN_BUF_SZ   (240 * 1024)

#define RESULT_EOF (-1)

typedef struct stdin_result
{
  hc_thread_cond_t *cond;

  char *buf;
  i32   cnt;

} stdin_result_t;

typedef struct stdin_req
{
  char *buf;

  stdin_result_t *result;

} stdin_req_t;

typedef struct stdin_ctx
{
  stdin_req_t requests[DEVICES_MAX];

  u8 reqs_head;
  u8 reqs_tail;

  // stdin read-thread mutexes

  hc_thread_mutex_t mux_request; // NOTE: always acquire _before_ acquiring mux_result below
  hc_thread_mutex_t mux_result;

  hc_thread_cond_t  cond_request; // signalled on new request

  bool eof;
  bool stop;

  i32 read_success_cnt;

  hashcat_ctx_t *hashcat_ctx;
  status_ctx_t  *status_ctx;

  #if defined (_WIN)
  HANDLE hnd;
  HANDLE read_event;

  bool is_console;
  #endif

  hc_thread_t read_thread;

} stdin_ctx_t;

int  stdin_open (stdin_ctx_t *stdin_ctx, hashcat_ctx_t *hashcat_ctx);
void stdin_stop (stdin_ctx_t *stdin_ctx);
void stdin_close (stdin_ctx_t *stdin_ctx);

void stdin_read_request (stdin_ctx_t *stdin_ctx, char *buf, stdin_result_t *result);
void stdin_read_wait (stdin_ctx_t *stdin_ctx, stdin_result_t *result);
void stdin_wait_exit (stdin_ctx_t *stdin_ctx);

#endif // _STDIN_H