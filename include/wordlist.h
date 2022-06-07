/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_WORDLIST_H
#define HC_WORDLIST_H

#include <time.h>
#include <inttypes.h>
#include <types.h>

size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len);

void pw_pre_add  (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx);
void pw_base_add (hc_device_param_t *device_param, pw_pre_t *pw_pre);
void pw_add      (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len);
void pw_add_raw  (u32 *pws_comp, pw_idx_t *pws_idx, u64 *pws_cnt, const u8 *pw_buf, const int pw_len);

void pw_in_buf_alloc (char **buf, char **alloc, size_t buf_len, u16 align, u16 blk_sz);

void get_next_word_lm  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_uc  (char *buf, u64 sz, u64 *len, u64 *off);
void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off);

void get_next_word   (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, char **out_buf, u32 *out_len);
int  load_segment    (hashcat_ctx_t *hashcat_ctx, HCFILE *fp);
int  count_words     (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *dictfile, u64 *result);

int  wl_data_init    (hashcat_ctx_t *hashcat_ctx);
void wl_data_destroy (hashcat_ctx_t *hashcat_ctx);

// pwd indexing and post-processing related

typedef struct host_proc_param
{
  hashcat_ctx_t *hashcat_ctx;

  bool    iconv_enabled;
  iconv_t iconv_ctx;
  char   *iconv_tmp;

  u32         rule_jk_len;
  const char *rule_jk_buf;

} host_proc_param_t;

typedef struct indexer_param
{
  char *next_line;
  char *buf_limit;

  u32      *pws_comp;
  pw_idx_t *pws_idx;

  u64 pws_cnt;
  u64 pws_cnt_max;

  u32 pw_min;
  u32 pw_max;

} indexer_param_t;

typedef u64 (*index_fn_t) (indexer_param_t *, host_proc_param_t *);

typedef struct indexer_cfg
{
  index_fn_t index_lines;

  u16 align;
  u16 blk_sz;

} indexer_cfg_t;

indexer_cfg_t get_indexer_cfg (bool fast_mode);

#endif // HC_WORDLIST_H
