/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STDIN_H
#define _STDIN_H

typedef struct stdin_ctx
{
  char *buf;
  char *head;  // start of next line
  char *check; // next char to check
  char *tail;  // next empty position

  char prev; // previous char checked

  bool eof;

  #if defined (_WIN)
  HANDLE hnd;
  HANDLE read_event;

  bool is_console;
  #endif

} stdin_ctx_t;

int   stdin_open (stdin_ctx_t *stdin_ctx);
void  stdin_close (stdin_ctx_t *stdin_ctx);

int   stdin_read (stdin_ctx_t *stdin_ctx);
char *stdin_next_line (stdin_ctx_t *stdin_ctx, size_t *line_len);

#define stdin_unchecked_len(s) ((int) ((s)->tail - (s)->check))

#endif // _STDIN_H