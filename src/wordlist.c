/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "dictstat.h"
#include "rp.h"
#include "rp_cpu.h"
#include "shared.h"
#include "wordlist.h"
#include "bitops.h"
#include "emu_inc_hash_sha1.h"

size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (line_len & 1) return (line_len); // not in hex

  if (hashconfig->opts_type & OPTS_TYPE_PT_HEX)
  {
    size_t i, j;

    for (i = 0, j = 0; j < line_len; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }

    memset (line_buf + i, 0, line_len - i);

    return (i);
  }

  if (user_options->wordlist_autohex == true)
  {
    if (is_hexify ((const u8 *) line_buf, line_len) == true)
    {
      const size_t new_len = exec_unhexify ((const u8 *) line_buf, line_len, (u8 *) line_buf, line_len);

      return new_len;
    }
  }

  return (line_len);
}

int load_segment (hashcat_ctx_t *hashcat_ctx, HCFILE *fp)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  // NOTE: use (never changing) ->incr here instead of ->avail otherwise the buffer gets bigger and bigger

  wl_data->pos = 0;

  wl_data->cnt = hc_fread (wl_data->buf, 1, wl_data->incr - 1000, fp);

  if (wl_data->cnt == (size_t) -1)
  {
    return -1;
  }

  wl_data->buf[wl_data->cnt] = 0;

  if (wl_data->cnt == 0) return 0;

  if (wl_data->buf[wl_data->cnt - 1] == '\n') return 0;

  while (!hc_feof (fp))
  {
    if (wl_data->cnt == wl_data->avail)
    {
      wl_data->buf = (char *) hcrealloc (wl_data->buf, wl_data->avail, wl_data->incr);

      wl_data->avail += wl_data->incr;
    }

    const int c = hc_fgetc (fp);

    if (c == EOF) break;

    wl_data->buf[wl_data->cnt] = (char) c;

    wl_data->cnt++;

    if (c == '\n') break;
  }

  // ensure stream ends with a newline

  if (wl_data->buf[wl_data->cnt - 1] != '\n')
  {
    wl_data->cnt++;

    wl_data->buf[wl_data->cnt - 1] = '\n';
  }

  return 0;
}

void get_next_word_lm_gen (char *buf, u64 sz, u64 *len, u64 *off, u64 cutlen)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (i == cutlen)
    {
      if (cutlen == 20) buf[i - 1]= ']'; // add ] in $HEX[] format

      *len = i;

      // but continue a loop to skip rest of the line
    }

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    if (i < cutlen + 1) *len = i;

    return;
  }

  *off = sz;

  if (sz < cutlen) *len = sz;
}

void get_next_word_lm_hex (char *buf, u64 sz, u64 *len, u64 *off)
{
  // this one is called if --hex-wordlist is used
  // we need 14 hex-digits to get 7 characters
  // but first convert 7 chars to upper case if they are a-z

  for (u64 i = 5; i < sz; i++)
  {
    if ((i & 1) == 0)
    {
      if (is_valid_hex_char (buf[i]))
        if (is_valid_hex_char (buf[i + 1]))
        {
          if (buf[i] == '6')
            if (buf[i+1] > '0')
              buf[i] = '4';
          if (buf[i] == '7')
            if (buf[i+1] < 'B')
              buf[i] = '5';
        }
    }

    if (i == 12) break;  // stop when 7 chars are converted
  }

  // call generic next_word

  get_next_word_lm_gen (buf, sz, len, off, 14);
}

void get_next_word_lm_hex_or_text (char *buf, u64 sz, u64 *len, u64 *off)
{
  // check if not $HEX[..] format
  bool hex = true;

  if (sz < 8) hex = false;

  if (hex && (buf[0] != '$')) hex = false;
  if (hex && (buf[1] != 'H')) hex = false;
  if (hex && (buf[2] != 'E')) hex = false;
  if (hex && (buf[3] != 'X')) hex = false;
  if (hex && (buf[4] != '[')) hex = false;

  if (hex)
  {
    char *ptr = buf + 5; // starting after '['

    for (u64 i = 5; i < sz; i++, ptr++)
    {
      if (*ptr == ']')
      {
        if ((i & 1) == 0) hex = false; // not even number of characters
        break;
      }
      else
      {
        if (is_valid_hex_char (*ptr) == false)
        {
          hex = false;
          break;
        }
        // upcase character if it is a letter 'a-z'
        if ((i & 1) == 1) // if first hex-char
        {
          if (is_valid_hex_char (buf[i + 1]))
          {
            if (buf[i] == '6')
              if (buf[i + 1] > '0')
                buf[i] = '4';
            if (buf[i] == '7')
              if (buf[i + 1] < 'B')
                buf[i] = '5';
          }
        }
      }
    }
  }
  if (hex)
  {
    //$HEX[] format so we need max 14 hex-digits + 6 chars '$HEX[]'
    get_next_word_lm_gen (buf, sz, len, off, 20);
  }
  else
  {
    // threat it as normal string
    get_next_word_lm_gen (buf, sz, len, off, 7);
  }
}

void get_next_word_lm_text (char *buf, u64 sz, u64 *len, u64 *off)
{
  get_next_word_lm_gen (buf, sz, len, off, 7);
}

void get_next_word_uc (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, char **out_buf, u32 *out_len)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  while (wl_data->pos < wl_data->cnt)
  {
    u64 off;
    u64 len;

    char *ptr = wl_data->buf + wl_data->pos;

    wl_data->func (ptr, wl_data->cnt - wl_data->pos, &len, &off);

    wl_data->pos += off;

    // do the on-the-fly hex decode using original buffer
    // this is safe as length only decreases in size

    len = (u32) convert_from_hex (hashcat_ctx, ptr, len);

    // do the on-the-fly encoding
    // needs to write into new buffer because size case both decrease and increase

    if (wl_data->iconv_enabled == true)
    {
      char  *iconv_ptr = wl_data->iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      size_t ptr_len = len;

      const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

      if (iconv_rc == (size_t) -1) continue;

      ptr = wl_data->iconv_tmp;
      len = HCBUFSIZ_TINY - iconv_sz;
    }

    // this is only a test for length, not writing into output buffer

    if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
    {
      if (len >= RP_PASSWORD_SIZE) continue;

      char rule_buf_out[RP_PASSWORD_SIZE];

      memset (rule_buf_out, 0, sizeof (rule_buf_out));

      const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, (u32) len, rule_buf_out);

      if (rule_len_out < 0) continue;
    }

    if (len > PW_MAX) continue;

    *out_buf = ptr;
    *out_len = (u32) len;

    return;
  }

  if (hc_feof (fp))
  {
    fprintf (stderr, "BUG feof()!!\n");

    return;
  }

  if (load_segment (hashcat_ctx, fp) == -1)
  {
    event_log_error (hashcat_ctx, "Error reading file!\n");

    return;
  }

  get_next_word (hashcat_ctx, fp, out_buf, out_len);
}

void pw_pre_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx)
{
  if (device_param->pws_pre_cnt < device_param->kernel_power)
  {
    pw_pre_t *pw_pre = device_param->pws_pre_buf + device_param->pws_pre_cnt;

    memcpy (pw_pre->pw_buf, pw_buf, pw_len);

    pw_pre->pw_len = pw_len;

    if (base_buf != NULL)
    {
      memcpy (pw_pre->base_buf, base_buf, base_len);

      pw_pre->base_len = base_len;
    }

    pw_pre->rule_idx = rule_idx;

    device_param->pws_pre_cnt++;
  }
  else
  {
    fprintf (stdout, "BUG pw_pre_add()!!\n");

    return;
  }
}

void pw_base_add (hc_device_param_t *device_param, pw_pre_t *pw_pre)
{
  if (device_param->pws_base_cnt < device_param->kernel_power)
  {
    memcpy (device_param->pws_base_buf + device_param->pws_base_cnt, pw_pre, sizeof (pw_pre_t));

    device_param->pws_base_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_base_add()!!\n");

    return;
  }
}

__attribute__ ((always_inline))
inline void pw_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len)
{
  if (device_param->pws_cnt < device_param->kernel_power)
  {
    pw_add_raw (device_param->pws_comp, device_param->pws_idx, &device_param->pws_cnt, pw_buf, pw_len);
  }
  else
  {
    fprintf (stderr, "BUG pw_add()!!\n");
  }
}

void pw_add_raw (u32 *pws_comp, pw_idx_t *pws_idx, u64 *pws_cnt, const u8 *pw_buf, const int pw_len)
{
  pw_idx_t *pw_idx = pws_idx + (*pws_cnt)++;

  const u32 pw_len4 = (pw_len + 3) & ~3; // round up to multiple of 4

  const u32 pw_len4_cnt = pw_len4 / 4;

  pw_idx->cnt = pw_len4_cnt;
  pw_idx->len = pw_len;

  u8 *pw_dest = (u8 *) (pws_comp + pw_idx->off);

  buf_cpy (pw_dest, pw_buf, pw_len);

  // pad zeros

  *(u32 *) (pw_dest + pw_len) = 0;

  // prepare next element

  pw_idx_t *pw_idx_next = pw_idx + 1;

  pw_idx_next->off = pw_idx->off + pw_idx->cnt;
}

int count_words (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, const char *dictfile, u64 *result)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  //hc_signal (NULL);

  dictstat_t d;

  memset (&d, 0, sizeof (d));

  if (hc_fstat (fp, &d.stat))
  {
    *result = 0;

    return 0;
  }

  d.stat.st_mode    = 0;
  d.stat.st_nlink   = 0;
  d.stat.st_uid     = 0;
  d.stat.st_gid     = 0;
  d.stat.st_rdev    = 0;
  d.stat.st_atime   = 0;

  #if defined (STAT_NANOSECONDS_ACCESS_TIME)
  d.stat.STAT_NANOSECONDS_ACCESS_TIME = 0;
  #endif

  #if defined (_POSIX)
  d.stat.st_blksize = 0;
  d.stat.st_blocks  = 0;
  #endif

  memset (d.encoding_from, 0, sizeof (d.encoding_from));
  memset (d.encoding_to,   0, sizeof (d.encoding_to));

  strncpy (d.encoding_from, user_options->encoding_from, sizeof (d.encoding_from) - 1);
  strncpy (d.encoding_to,   user_options->encoding_to,   sizeof (d.encoding_to)   - 1);

  if (d.stat.st_size == 0)
  {
    *result = 0;

    return 0;
  }

  const size_t dictfile_len = strlen (dictfile);

  u32 *dictfile_padded = (u32 *) hcmalloc (dictfile_len + 64); // padding required for sha1_update()

  memcpy (dictfile_padded, dictfile, dictfile_len);

  for (size_t i = 0, j = 0; i < dictfile_len; i += 4, j += 1)
  {
    dictfile_padded[j] = byte_swap_32 (dictfile_padded[j]);
  }

  sha1_ctx_t sha1_ctx;
  sha1_init   (&sha1_ctx);
  sha1_update (&sha1_ctx, dictfile_padded, dictfile_len);
  sha1_final  (&sha1_ctx);

  sha1_ctx.h[0] = byte_swap_32 (sha1_ctx.h[0]);
  sha1_ctx.h[1] = byte_swap_32 (sha1_ctx.h[1]);
  sha1_ctx.h[2] = byte_swap_32 (sha1_ctx.h[2]);
  sha1_ctx.h[3] = byte_swap_32 (sha1_ctx.h[3]);
  sha1_ctx.h[4] = byte_swap_32 (sha1_ctx.h[4]);

  hcfree (dictfile_padded);

  memcpy (d.hash_filename, sha1_ctx.h, 16);

  const u64 cached_cnt = dictstat_find (hashcat_ctx, &d);

  if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l) == 0)
  {
    if (cached_cnt)
    {
      u64 keyspace = cached_cnt;

      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (overflow_check_u64_mul (keyspace, straight_ctx->kernel_rules_cnt) == true) return -1;

        keyspace *= straight_ctx->kernel_rules_cnt;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (overflow_check_u64_mul (keyspace, mask_ctx->bfs_cnt) == true) return -1;

          keyspace *= mask_ctx->bfs_cnt;
        }
        else
        {
          if (overflow_check_u64_mul (keyspace, combinator_ctx->combs_cnt) == true) return -1;

          keyspace *= combinator_ctx->combs_cnt;
        }
      }

      cache_hit_t cache_hit;

      cache_hit.dictfile      = dictfile;
      cache_hit.stat.st_size  = d.stat.st_size;
      cache_hit.cached_cnt    = cached_cnt;
      cache_hit.keyspace      = keyspace;

      EVENT_DATA (EVENT_WORDLIST_CACHE_HIT, &cache_hit, sizeof (cache_hit));

      *result = keyspace;

      return 0;
    }
  }

  time_t rt_start;

  time (&rt_start);

  time_t now  = 0;
  time_t prev = 0;

  u64 comp = 0;
  u64 cnt  = 0;
  u64 cnt2 = 0;

  while (!hc_feof (fp))
  {
    if (load_segment (hashcat_ctx, fp) == -1)
    {
      return -2;
    }

    comp += wl_data->cnt;

    u64 i = 0;

    while (i < wl_data->cnt)
    {
      u64 len;
      u64 off;

      char *ptr = wl_data->buf + i;

      wl_data->func (ptr, wl_data->cnt - i, &len, &off);

      i += off;

      // do the on-the-fly hex decode using original buffer
      // this is safe as length only decreases in size

      len = (u32) convert_from_hex (hashcat_ctx, ptr, len);

      // do the on-the-fly encoding

      if (wl_data->iconv_enabled == true)
      {
        char  *iconv_ptr = wl_data->iconv_tmp;
        size_t iconv_sz  = HCBUFSIZ_TINY;

        size_t ptr_len = len;

        const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

        if (iconv_rc == (size_t) -1) continue;

        ptr = wl_data->iconv_tmp;
        len = HCBUFSIZ_TINY - iconv_sz;
      }

      if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
      {
        if (len >= RP_PASSWORD_SIZE) continue;

        char rule_buf_out[RP_PASSWORD_SIZE];

        memset (rule_buf_out, 0, sizeof (rule_buf_out));

        const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, (u32) len, rule_buf_out);

        if (rule_len_out < 0) continue;
      }

      cnt2++;

      if (len > PW_MAX) continue;

      d.cnt++;

      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (overflow_check_u64_add (cnt, straight_ctx->kernel_rules_cnt) == true) return -1;

        cnt += straight_ctx->kernel_rules_cnt;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (overflow_check_u64_add (cnt, mask_ctx->bfs_cnt) == true) return -1;

          cnt += mask_ctx->bfs_cnt;
        }
        else
        {
          if (overflow_check_u64_add (cnt, combinator_ctx->combs_cnt) == true) return -1;

          cnt += combinator_ctx->combs_cnt;
        }
      }
    }

    time (&now);

    if ((now - prev) == 0) continue;

    time (&prev);

    double percent = ((double) comp / (double) d.stat.st_size) * 100;

    if (percent < 100)
    {
      cache_generate_t cache_generate;

      cache_generate.dictfile    = dictfile;
      cache_generate.comp        = comp;
      cache_generate.percent     = percent;
      cache_generate.cnt         = cnt;
      cache_generate.cnt2        = cnt2;

      EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));
    }
  }

  time_t rt_stop;

  time (&rt_stop);

  cache_generate_t cache_generate;

  cache_generate.dictfile    = dictfile;
  cache_generate.comp        = comp;
  cache_generate.percent     = 100;
  cache_generate.cnt         = cnt;
  cache_generate.cnt2        = cnt2;
  cache_generate.runtime     = rt_stop - rt_start;

  EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));

  dictstat_append (hashcat_ctx, &d);

  //hc_signal (sigHandler_default);

  *result = cnt;

  return 0;
}

int wl_data_init (hashcat_ctx_t *hashcat_ctx)
{
  wl_data_t      *wl_data      = hashcat_ctx->wl_data;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  wl_data->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->benchmark    == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->version      == true) return 0;

  wl_data->enabled = true;

  wl_data->buf     = (char *) hcmalloc (user_options->segment_size);
  wl_data->avail   = user_options->segment_size;
  wl_data->incr    = user_options->segment_size;
  wl_data->cnt     = 0;
  wl_data->pos     = 0;

  /**
   * choose dictionary parser
   */

  wl_data->func = get_next_word_std;

  if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
  {
    wl_data->func = get_next_word_uc;
  }

  if (hashconfig->opts_type & OPTS_TYPE_PT_LM)
  {
    if (hashconfig->opts_type & OPTS_TYPE_PT_HEX)
    {
      wl_data->func = get_next_word_lm_hex;           // all hex in file
    }
    else
    {
      if (user_options->wordlist_autohex == true)
      {
        wl_data->func = get_next_word_lm_hex_or_text; // might be $HEX[] notation
      }
      else
      {
        wl_data->func = get_next_word_lm_text;        // treat as normal text
      }
    }
  }

  /**
   * iconv
   */

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    wl_data->iconv_enabled = true;

    wl_data->iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (wl_data->iconv_ctx == (iconv_t) -1) return -1;

    wl_data->iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  return 0;
}

void wl_data_destroy (hashcat_ctx_t *hashcat_ctx)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  if (wl_data->enabled == false) return;

  hcfree (wl_data->buf);

  if (wl_data->iconv_enabled == true)
  {
    iconv_close (wl_data->iconv_ctx);

    wl_data->iconv_enabled = false;

    hcfree (wl_data->iconv_tmp);
  }

  memset (wl_data, 0, sizeof (wl_data_t));
}

// input buffer constants for pwd indexing

#define IN_BUF_ALIGN_DEFAULT 16
#define IN_BUF_ALIGN_AVX2    64 // meets _m256i needs (align to 32) and cache-line friendly

#define IN_BUF_BLOCK_SZ_DEFAULT 16  // allow for 128-bit (16 byte) vector overrun
#define IN_BUF_BLOCK_SZ_AVX2    256 // 8 * 256-bit (32 byte) vectors/stripes

#define IN_BUF_MAX_SZ (UINT32_MAX - IN_BUF_ALIGN_AVX2) // allow positions that include alignment offset within u32 range

// default batched password indexing (with host-side post-processing)

#if !defined (__APPLE__) // function multi-versioning not available on MacOS (non-ELF targets)
__attribute__ ((target ("default")))
#endif
static u64 index_lines_default (indexer_param_t *indexer_param, host_proc_param_t *host_proc_param)
{
  const char *buf_limit        = indexer_param->buf_limit;
  const u64   pws_cnt_max      = indexer_param->pws_cnt_max;
  const u32   pw_min           = indexer_param->pw_min;
  const u32   pw_max           = indexer_param->pw_max;

  char     *restrict next_line = indexer_param->next_line;
  u32      *restrict pws_comp  = indexer_param->pws_comp;
  pw_idx_t *restrict pws_idx   = indexer_param->pws_idx;
  u64 pws_cnt                  = indexer_param->pws_cnt;

  hashcat_ctx_t *hashcat_ctx   = host_proc_param->hashcat_ctx;

  const bool     iconv_enabled = host_proc_param->iconv_enabled;
  iconv_t        iconv_ctx     = host_proc_param->iconv_ctx;
  char          *iconv_tmp     = host_proc_param->iconv_tmp;

  int            rule_jk_len   = (int) host_proc_param->rule_jk_len;
  const char    *rule_jk_buf   = host_proc_param->rule_jk_buf;
  // TODO caching this result improves indexing rate by 1-2% but unsure if the rule buf
  //      is dynamic and that caching this breaks things... maybe remove
  const bool     run_rule_eng  = (run_rule_engine (rule_jk_len, rule_jk_buf) != 0);

  u64 words_extra = 0;

  while (pws_cnt < pws_cnt_max)
  {
    if (next_line >= buf_limit) break;

    // move to the next line (relies on '\n' sentinel)

    char *line_buf = next_line;

    char prev = '\0';

    while (*next_line != '\n') prev = *next_line++;

    size_t line_len = next_line - line_buf;

    if (prev == '\r') line_len--;

    next_line++;

    line_len = convert_from_hex (hashcat_ctx, line_buf, (u32) line_len);

    // do the on-the-fly encoding

    if (iconv_enabled == true)
    {
      char  *iconv_ptr = iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      if (iconv (iconv_ctx, &line_buf, &line_len, &iconv_ptr, &iconv_sz) == (size_t) -1) continue;

      line_buf = iconv_tmp;
      line_len = HCBUFSIZ_TINY - iconv_sz;
    }

    // post-process rule engine

    char rule_buf_out[RP_PASSWORD_SIZE];

    if (run_rule_eng == true)
    {
      if (line_len >= RP_PASSWORD_SIZE) continue;

      memset (rule_buf_out, 0, sizeof (rule_buf_out));

      const int rule_len_out = _old_apply_rule (rule_jk_buf, rule_jk_len, line_buf, (int) line_len, rule_buf_out);

      if (rule_len_out < 0) continue;

      line_buf = rule_buf_out;
      line_len = (size_t) rule_len_out;
    }

    // hmm that's always the case, or?

    if ((line_len < pw_min) || (line_len > pw_max))
    {
      if (line_len <= PW_MAX) words_extra++;

      continue;
    }

    pw_add_raw (pws_comp, pws_idx, &pws_cnt, (const u8 *) line_buf, (const int) line_len);
  }

  indexer_param->next_line = next_line;
  indexer_param->pws_cnt   = pws_cnt;

  return words_extra;
}

#if !defined (__APPLE__) // function multi-versioning not available on MacOS (non-ELF targets)
__attribute__ ((target ("default")))
#endif
u64 index_lines_fast (indexer_param_t *indexer_param, host_proc_param_t *host_proc_param)
{
  (void) *host_proc_param; // host post-processing params ignored

  const char *buf_limit        = indexer_param->buf_limit;
  const u64   pws_cnt_max      = indexer_param->pws_cnt_max;
  const u32   pw_min           = indexer_param->pw_min;
  const u32   pw_max           = indexer_param->pw_max;

  char     *restrict next_line = indexer_param->next_line;
  u32      *restrict pws_comp  = indexer_param->pws_comp;
  pw_idx_t *restrict pws_idx   = indexer_param->pws_idx;
  u64 pws_cnt                  = indexer_param->pws_cnt;

  u64 words_extra = 0;

  while (pws_cnt < pws_cnt_max)
  {
    if (next_line >= buf_limit) break;

    // move to the next line (relies on '\n' sentinel)

    char *line_buf = next_line;

    char prev = '\0';

    while (*next_line != '\n') prev = *next_line++;

    size_t line_len = next_line - line_buf;

    if (prev == '\r') line_len--;

    next_line++;

    // hmm that's always the case, or?

    if ((line_len < pw_min) || (line_len > pw_max))
    {
      if (line_len <= PW_MAX) words_extra++;

      continue;
    }

    pw_add_raw (pws_comp, pws_idx, &pws_cnt, (const u8 *) line_buf, (const int) line_len);
  }

  indexer_param->next_line = next_line;
  indexer_param->pws_cnt   = pws_cnt;

  return words_extra;
}

// AVX2 vectored password indexing

#if !defined (__APPLE__) // function multi-versioning not available on MacOS (non-ELF targets)

#include <immintrin.h>

#include "assert.h"

#define AVX2_STRIPE_SZ  32
#define AVX2_STRIPE_CNT (IN_BUF_BLOCK_SZ_AVX2 / AVX2_STRIPE_SZ)

// vector/stripe identifiers

#define A 0
#define B 1
#define C 2
#define D 3
#define E 4
#define F 5
#define G 6
#define H 7

// alignment shorthands

#define aligned(x) __attribute__ ((aligned (x)))
#define assume_aligned(x, a) __builtin_assume_aligned (x, a)

__attribute__ ((target ("avx2,popcnt,bmi,lzcnt")))
u64 index_lines_fast_avx2 (indexer_param_t *indexer_param, host_proc_param_t *host_proc_param)
{
  (void) *host_proc_param; // host post-processing params ignored

  const u32 src_len           = (u32) (indexer_param->buf_limit - indexer_param->next_line);
  const u32 pw_min            = indexer_param->pw_min;
  const u32 pw_max            = indexer_param->pw_max;
  const u32 pws_cnt_max       = indexer_param->pws_cnt_max;

  char     *restrict src_buf  = indexer_param->next_line;
  u32      *restrict pws_comp = indexer_param->pws_comp;
  pw_idx_t *restrict pws_idx  = indexer_param->pws_idx;
  u64 pws_cnt                 = indexer_param->pws_cnt;

  // restrict src buffer size so that we can use u32 values to track buf positions that include
  // an alignment offset of up to (IN_BUF_ALIGN_AVX2 - 1)

  assert (src_len <= IN_BUF_MAX_SZ);

  // NOTE: currently we require that src_buf (aka indexer_param->next_line) is a pointer to a buffer such that:
  //   1) src_buf is either 64-byte aligned or is pre-padded (at least) to its previous 64-byte alignment
  //      i.e. src_buf - ((uintptr_t) src_buf & 63) always points to a valid memory location
  //   2) Any 256 byte block starting from and aligned with (src_buf & 63), up to and including
  //      src_buf + (src_len - 1) points to valid memory.
  //      i.e. (src_buf & ~63) + ((src_len + (64 - (*src_buf & 63))) & 255) + 256 is always a valid
  //      memory location
  //   TLDR: just use pw_in_buf_alloc() to allocate src_buf!

  const __m256i NL_CMP         = _mm256_set1_epi8 ((u8) '\n');
  const __m256i CR_CMP         = _mm256_set1_epi8 ((u8) '\r');

  const __m256i ROTL_PERM      = _mm256_set_epi32(6, 5, 4, 3, 2, 1, 0, 7); // control vector: rotate 32-bit elements 1 position right

  const __m256i NL_TZ_LIMIT    = _mm256_set1_epi32 (32);

  const __m256i PW_LEN_MIN     = _mm256_set1_epi32 ((int) pw_min);
  const __m256i PW_LEN_MAX     = _mm256_set1_epi32 ((int) pw_max);

  const __m256i ZEROS          = _mm256_setzero_si256 ();
  const __m256i ONES_8x32      = _mm256_set1_epi32 (1);
  const __m256i THREES_8x32    = _mm256_set1_epi32 (3);

  const __m256i BLOCK_LENS     = _mm256_set1_epi32 (IN_BUF_BLOCK_SZ_AVX2);

  const __m256i IDX_NULL_OFFS  = _mm256_set1_epi32 ((int) pws_cnt_max);

  const u64 pws_cnt_prev = pws_cnt;
  const u64 offset       = (uintptr_t) src_buf & (IN_BUF_ALIGN_AVX2 - 1);
  const u64 src_end      = src_len + offset;

  const char *in_buf = assume_aligned (src_buf - offset, IN_BUF_ALIGN_AVX2); // pointer to first block (alignment padded)

  u32 line_pstns_arr[AVX2_STRIPE_CNT] aligned (32);

  u64 words_extra = 0;

  // block index (64-byte aligned)

  u32 block_start = 0;

  __m256i stripe_pstns = _mm256_setr_epi32
  (
    AVX2_STRIPE_SZ * 0,
    AVX2_STRIPE_SZ * 1,
    AVX2_STRIPE_SZ * 2,
    AVX2_STRIPE_SZ * 3,
    AVX2_STRIPE_SZ * 4,
    AVX2_STRIPE_SZ * 5,
    AVX2_STRIPE_SZ * 6,
    AVX2_STRIPE_SZ * 7
  );

  __m256i line_pstns = _mm256_insert_epi32 (stripe_pstns, offset, 0);

  u32 skip_masks[2];

  skip_masks[A] = (offset < 32) ? (UINT32_MAX << offset) : 0;
  skip_masks[B] = (offset < 32) ? UINT32_MAX : (UINT32_MAX << (offset - 32));

  bool final_block = false;

  u32 cr_mask_h_prev = 0;

  // setup output

  pw_idx_t *pws_idx_cur = pws_idx + pws_cnt;

  u32 pws_comp_off = pws_idx_cur->off;

  // outer loop, one iteration per block of input buffer

  while (final_block == false)
  {
    __m256i *block = (__m256i *) assume_aligned (in_buf + block_start, IN_BUF_ALIGN_AVX2);

    // truncation count (byte count of overshoot for this block, negative if no overshoot)

    const i64 trunc_cnt = ((i64) block_start + IN_BUF_BLOCK_SZ_AVX2) - (i64) src_end;

    // bitfields representing newline (NL) and carriage-return (CR) positions

    u32 nl_masks_arr[AVX2_STRIPE_CNT] aligned (32);

    __m256i nl_masks, cr_masks;

    // load data for this block

    __m256i buf_a_vec = _mm256_load_si256 (block + A);
    __m256i buf_b_vec = _mm256_load_si256 (block + B);
    __m256i buf_c_vec = _mm256_load_si256 (block + C);
    __m256i buf_d_vec = _mm256_load_si256 (block + D);
    __m256i buf_e_vec = _mm256_load_si256 (block + E);
    __m256i buf_f_vec = _mm256_load_si256 (block + F);
    __m256i buf_g_vec = _mm256_load_si256 (block + G);
    __m256i buf_h_vec = _mm256_load_si256 (block + H);

    // populate NL bitfields

    nl_masks_arr[A] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_a_vec, NL_CMP));
    nl_masks_arr[B] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_b_vec, NL_CMP));
    nl_masks_arr[C] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_c_vec, NL_CMP));
    nl_masks_arr[D] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_d_vec, NL_CMP));
    nl_masks_arr[E] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_e_vec, NL_CMP));
    nl_masks_arr[F] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_f_vec, NL_CMP));
    nl_masks_arr[G] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_g_vec, NL_CMP));
    nl_masks_arr[H] = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_h_vec, NL_CMP));

    // populate CR bitfields

    u32 cr_mask_h = _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_h_vec, CR_CMP));

    cr_masks = _mm256_setr_epi32
    (
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_a_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_b_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_c_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_d_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_e_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_f_vec, CR_CMP)),
      _mm256_movemask_epi8 (_mm256_cmpeq_epi8 (buf_g_vec, CR_CMP)),
      (int) cr_mask_h
    );

    // shift entire CR bitmask vector one bit left feeding overflow from previous block into rightmost bit, this aligns
    // CR mask bits with NL mask bits such that adjacent CR + NL pairs now have the same bit position

    __m256i crs_rotl     = _mm256_insert_epi32 (_mm256_permutevar8x32_epi32 (cr_masks, ROTL_PERM), cr_mask_h_prev, 0);
    __m256i cr_overflows = _mm256_srli_epi32 (crs_rotl, 31);

    cr_masks = _mm256_or_si256 (_mm256_slli_epi32 (cr_masks, 1), cr_overflows);

    cr_mask_h_prev = cr_mask_h; // keep for overflow into next round's CR masks

    // skip the alignment offset on first block

    if (unlikely (skip_masks[0] != UINT32_MAX))
    {
      nl_masks_arr[A] &= skip_masks[A];
      nl_masks_arr[B] &= skip_masks[B];

      skip_masks[A] = UINT32_MAX;
      skip_masks[B] = UINT32_MAX;
    }

    // truncate NL bitfields if we would overrun src buffer

    if (unlikely (trunc_cnt > 0))
    {
      assert (trunc_cnt < IN_BUF_BLOCK_SZ_AVX2);

      u8 idx   = (AVX2_STRIPE_CNT - 1) - (trunc_cnt / AVX2_STRIPE_SZ);
      u8 shift = trunc_cnt & (AVX2_STRIPE_SZ - 1);

      nl_masks_arr[idx] &= (UINT32_MAX >> shift);

      for (idx++; idx < AVX2_STRIPE_CNT; idx++) nl_masks_arr[idx] = 0;
    }

    // get the newline count for each stripe in the block

    // TODO consider using AVX2 approach here: https://github.com/WojciechMula/sse-popcount

    u32 nl_cnts_arr[AVX2_STRIPE_CNT];

    nl_cnts_arr[A] = (u32) _mm_popcnt_u32 (nl_masks_arr[A]);
    nl_cnts_arr[B] = (u32) _mm_popcnt_u32 (nl_masks_arr[B]);
    nl_cnts_arr[C] = (u32) _mm_popcnt_u32 (nl_masks_arr[C]);
    nl_cnts_arr[D] = (u32) _mm_popcnt_u32 (nl_masks_arr[D]);
    nl_cnts_arr[E] = (u32) _mm_popcnt_u32 (nl_masks_arr[E]);
    nl_cnts_arr[F] = (u32) _mm_popcnt_u32 (nl_masks_arr[F]);
    nl_cnts_arr[G] = (u32) _mm_popcnt_u32 (nl_masks_arr[G]);
    nl_cnts_arr[H] = (u32) _mm_popcnt_u32 (nl_masks_arr[H]);

    // find the total count and max count of newlines for all stripes

    u16 blk_nl_cnt = 0;
    u16 max_nl_cnt = 0;

    for (u8 i = 0; i < AVX2_STRIPE_CNT; i++)
    {
      blk_nl_cnt += nl_cnts_arr[i];
      max_nl_cnt  = (nl_cnts_arr[i] > max_nl_cnt) ? nl_cnts_arr[i] : max_nl_cnt;
    }

    // check for the possibility that we exceed pws_cnt_max and cap the output count
    // note: if passwords are subsequently rejected due to length bounds this will
    //       result in *pws_cnt < pws_cnt_max when returning

    u64 pws_remaining  = pws_cnt_max - pws_cnt;

    if (unlikely (blk_nl_cnt > pws_remaining))
    {
      final_block = true;

      blk_nl_cnt = 0;
      max_nl_cnt = 0;

      u8 i = 0;

      for ( ; (blk_nl_cnt + nl_cnts_arr[i]) <= pws_remaining; i++)
      {
        blk_nl_cnt += nl_cnts_arr[i];
        max_nl_cnt  = (nl_cnts_arr[i] > max_nl_cnt) ? nl_cnts_arr[i] : max_nl_cnt;
      }

      u32 target = pws_remaining - blk_nl_cnt;

      if (target > 0)
      {
        while (nl_cnts_arr[i] != target)
        {
          u32 shift = _lzcnt_u32 (nl_masks_arr[i]) + (nl_cnts_arr[i] - target);

          nl_masks_arr[i] &= (UINT32_MAX >> shift);
          nl_cnts_arr[i]   = (u32) _mm_popcnt_u32 (nl_masks_arr[i]);
        }

        max_nl_cnt = (nl_cnts_arr[i] > max_nl_cnt) ? nl_cnts_arr[i] : max_nl_cnt;

        i++;
      }

      for ( ; i < AVX2_STRIPE_CNT; i++)
      {
        nl_masks_arr[i] = 0;
        nl_cnts_arr[i]  = 0;
      }

      blk_nl_cnt = pws_remaining;
    }

    nl_masks = _mm256_load_si256 ((__m256i *) &nl_masks_arr[0]);

    // setup per-stripe base offsets for writing pwd indexes

    u32 idx_bases[AVX2_STRIPE_CNT] aligned (32);  // per-stripe base offsets from start of pws_idx

    idx_bases[A] = pws_cnt;
    idx_bases[B] = idx_bases[A] + nl_cnts_arr[A];
    idx_bases[C] = idx_bases[B] + nl_cnts_arr[B];
    idx_bases[D] = idx_bases[C] + nl_cnts_arr[C];
    idx_bases[E] = idx_bases[D] + nl_cnts_arr[D];
    idx_bases[F] = idx_bases[E] + nl_cnts_arr[E];
    idx_bases[G] = idx_bases[F] + nl_cnts_arr[F];
    idx_bases[H] = idx_bases[G] + nl_cnts_arr[G];

    __m256i idx_offsets = _mm256_load_si256 ((__m256i *) &idx_bases[0]);

    bool bounds_ok = true;

    // password indexing loop, each iteration yields 0 or 1 pwd index per 'stripe'

    for (u32 i = 0; i < max_nl_cnt; i++)
    {
      _mm256_store_si256 ((__m256i *) &line_pstns_arr[0], line_pstns);

      // byte indexes of newlines within respective vector 'lanes' (64 byte width)

      // TODO checkout out following techniques for vectorized lzcnt/tzcnt:
      //   https://stackoverflow.com/questions/56153183/is-using-avx2-can-implement-a-faster-processing-of-lzcnt-on-a-word-array
      //   https://old.reddit.com/r/simd/comments/b3k1oa/looking_for_sseavx_bitscan_discussions/
      //   https://gist.github.com/aqrit/79a76ef29046b2d42eafc6b1eb0bb518

      __m256i nl_tzs  = _mm256_setr_epi32
      (
        (int) _tzcnt_u32 (nl_masks_arr[A]),
        (int) _tzcnt_u32 (nl_masks_arr[B]),
        (int) _tzcnt_u32 (nl_masks_arr[C]),
        (int) _tzcnt_u32 (nl_masks_arr[D]),
        (int) _tzcnt_u32 (nl_masks_arr[E]),
        (int) _tzcnt_u32 (nl_masks_arr[F]),
        (int) _tzcnt_u32 (nl_masks_arr[G]),
        (int) _tzcnt_u32 (nl_masks_arr[H])
      );

      // positions in buffer of next newlines

      __m256i cur_nls = _mm256_sllv_epi32 (ONES_8x32, nl_tzs);

      // calculate CR+NL pwd length modifier (elements are 1 if '\r\n' combination present, 0 otherwise)

      __m256i cur_cr_nls    = _mm256_and_si256 (cur_nls, cr_masks); // bitfields of each stripe's next CR+NL combos (if any)
      __m256i crnl_len_mods = _mm256_add_epi32 (_mm256_cmpeq_epi32 (cur_cr_nls, ZEROS), ONES_8x32);

      // clear current newlines from masks

      nl_masks = _mm256_andnot_si256 (cur_nls, nl_masks);

      _mm256_store_si256 ((__m256i *) &nl_masks_arr[A], nl_masks);

      // line-length and buffer position calculation

      __m256i nl_pstns  = _mm256_add_epi32 (nl_tzs, stripe_pstns);
      __m256i has_nls   = _mm256_cmpgt_epi32 (NL_TZ_LIMIT, nl_tzs);

      __m256i lens      = _mm256_sub_epi32 (_mm256_sub_epi32 (nl_pstns, line_pstns), crnl_len_mods);
      __m256i len4s     = _mm256_andnot_si256 (THREES_8x32, _mm256_add_epi32 (lens, THREES_8x32));
      __m256i len4_cnts = _mm256_srli_epi32 (len4s, 2);

      // batch detect out-of-bounds password lengths

      __m256i bounds_broken = _mm256_cmpgt_epi32 (lens, PW_LEN_MAX);

      if (unlikely (pw_min > 0))
      {
        __m256i lt_min = _mm256_cmpgt_epi32 (PW_LEN_MIN, lens);
        bounds_broken  = _mm256_or_si256 (bounds_broken, lt_min);
      }

      // see: https://stackoverflow.com/a/67228970
      bounds_ok &= _mm256_testz_si256 (bounds_broken, bounds_broken) != 0;

      u32 lens_arr      [AVX2_STRIPE_CNT] aligned (32);
      u32 len4_cnts_arr [AVX2_STRIPE_CNT] aligned (32);

      _mm256_store_si256 ((__m256i *) &lens_arr[0],      lens);
      _mm256_store_si256 ((__m256i *) &len4_cnts_arr[0], len4_cnts);

      // store pwd index write offsets, blending with 'null' offset (i.e. discard) where no newline present

      u32 idx_dsts_arr[AVX2_STRIPE_CNT] aligned (32);

      __m256i idx_dsts = _mm256_blendv_epi8 (IDX_NULL_OFFS, idx_offsets, has_nls);

      _mm256_store_si256 ((__m256i *) &idx_dsts_arr[0], idx_dsts);

      // write the password indexes in place, we use the .off field to store the password start index offset from
      // in_buf. This gets replaced with the actual offset of the password in the compressed password buffer
      // when the password bytes are copied over.

      pws_idx[idx_dsts_arr[A]] = (pw_idx_t) { .cnt = len4_cnts_arr[A], .len = lens_arr[A], .off = line_pstns_arr[A] };
      pws_idx[idx_dsts_arr[B]] = (pw_idx_t) { .cnt = len4_cnts_arr[B], .len = lens_arr[B], .off = line_pstns_arr[B] };
      pws_idx[idx_dsts_arr[C]] = (pw_idx_t) { .cnt = len4_cnts_arr[C], .len = lens_arr[C], .off = line_pstns_arr[C] };
      pws_idx[idx_dsts_arr[D]] = (pw_idx_t) { .cnt = len4_cnts_arr[D], .len = lens_arr[D], .off = line_pstns_arr[D] };
      pws_idx[idx_dsts_arr[E]] = (pw_idx_t) { .cnt = len4_cnts_arr[E], .len = lens_arr[E], .off = line_pstns_arr[E] };
      pws_idx[idx_dsts_arr[F]] = (pw_idx_t) { .cnt = len4_cnts_arr[F], .len = lens_arr[F], .off = line_pstns_arr[F] };
      pws_idx[idx_dsts_arr[G]] = (pw_idx_t) { .cnt = len4_cnts_arr[G], .len = lens_arr[G], .off = line_pstns_arr[G] };
      pws_idx[idx_dsts_arr[H]] = (pw_idx_t) { .cnt = len4_cnts_arr[H], .len = lens_arr[H], .off = line_pstns_arr[H] };

      idx_offsets = _mm256_add_epi32 (idx_offsets, ONES_8x32);

      // update line positions

      line_pstns = _mm256_blendv_epi8 (line_pstns, _mm256_add_epi32 (nl_pstns, ONES_8x32), has_nls);
    } // for-loop

    // 'fuse' the last result in each stripe with the first of the next stripe, whilst
    // propagating the last line position through the stripes

    // if a stripe had at least one newline, its first result needs fusing with the previous
    // stripe, except for the leading stripe which always has correct value (either initial value
    // from the first block, or the trailing position from previous round)

    u32 stripe_pstns_arr[AVX2_STRIPE_CNT] aligned (32);

    _mm256_store_si256 ((__m256i *) &stripe_pstns_arr[0], stripe_pstns);
    _mm256_store_si256 ((__m256i *) &line_pstns_arr[0], line_pstns);

    #define fuse_stripes(S,T)                                                                      \
    ({                                                                                             \
      if (likely (nl_cnts_arr[T] > 0))                                                             \
      {                                                                                            \
        pw_idx_t *pw_idx = &pws_idx[idx_bases[T]];                                                 \
        u32 len          = (stripe_pstns_arr[T] - line_pstns_arr[S]) + pw_idx->len;                \
                                                                                                   \
        bounds_ok &= (len <= pw_max); /* pwd can only increase in length here */                   \
                                                                                                   \
        pw_idx->len = len;                                                                         \
        pw_idx->cnt = ((len + 3) & ~3) / 4;                                                        \
        pw_idx->off = line_pstns_arr[S];                                                           \
      }                                                                                            \
      else                                                                                         \
      {                                                                                            \
        line_pstns_arr[T] = line_pstns_arr[S];                                                     \
      }                                                                                            \
    })

    fuse_stripes (A,B);
    fuse_stripes (B,C);
    fuse_stripes (C,D);
    fuse_stripes (D,E);
    fuse_stripes (E,F);
    fuse_stripes (F,G);
    fuse_stripes (G,H);

    // copy passwords from source buffer

    #define pw_copy()                                                                               \
    ({                                                                                              \
      const char *restrict pw_src = in_buf + pws_idx_cur->off; /* .off is currently src offset */   \
                                                                                                    \
      pws_idx_cur->off = pws_comp_off;                         /* update .off to dest offset */     \
                                                                                                    \
      char *restrict pw_dst = (char *) (pws_comp + pws_comp_off);                                   \
                                                                                                    \
      pws_comp_off += pws_idx_cur->cnt;                                                             \
                                                                                                    \
      const u32 len = pws_idx_cur->len;                                                             \
                                                                                                    \
      pws_idx_cur++;                                                                                \
                                                                                                    \
      u32 *padding = (u32 *) (pw_dst + len);                                                        \
                                                                                                    \
      switch (len / 16)                                                                             \
      {                                                                                             \
        default : memcpy ((void *) pw_dst, (void *) pw_src, len);   /* pwd len: 64...  */           \
                                                                                                    \
                  *padding = 0;                                                                     \
                                                                                                    \
                  continue;                                                                         \
                                                                                                    \
        case 3:   ((char16 *) pw_dst)[3] = ((char16 *) pw_src)[3];  /* pwd len: 47..63 */           \
                  /* fall-through */                                                                \
        case 2:   ((char16 *) pw_dst)[2] = ((char16 *) pw_src)[2];  /* pwd len: 32..47 */           \
                  /* fall-through */                                                                \
        case 1:   ((char16 *) pw_dst)[1] = ((char16 *) pw_src)[1];  /* pwd len: 16..31 */           \
                  /* fall-through */                                                                \
        case 0:   ((char16 *) pw_dst)[0] = ((char16 *) pw_src)[0];  /* pwd len:  0..15 */           \
                                                                                                    \
                  *padding = 0;                                                                     \
                                                                                                    \
                  continue;                                                                         \
      }                                                                                             \
    })

    pw_idx_t *limit = pws_idx_cur + blk_nl_cnt;

    if (bounds_ok == true)
    {
      // copy passwords with no bounds checks

      while (pws_idx_cur < limit) pw_copy ();

      pws_cnt += blk_nl_cnt;
    }
    else
    {
      // check and copy each password iff within length bounds

      pw_idx_t *pws_idx_start = pws_idx_cur;
      pw_idx_t *pws_idx_src   = pws_idx_cur;

      while (pws_idx_src < limit)
      {
        if ((pws_idx_src->len < pw_min) || (pws_idx_src->len > pw_max))
        {
          if (pws_idx_src->len <= PW_MAX) words_extra++;

          pws_idx_src++;

          continue;
        }

        *pws_idx_cur = *pws_idx_src++;

        pw_copy ();
      }

      pws_cnt += (u64) (pws_idx_cur - pws_idx_start);
    }

    // prepare for next block

    block_start += IN_BUF_BLOCK_SZ_AVX2;

    stripe_pstns = _mm256_add_epi32 (stripe_pstns, BLOCK_LENS);

    // assign stripe start positions as temp line positions for next iteration (will get fused later)
    // except for AB stripe which is assigned the current block's trailing line position

    line_pstns = _mm256_insert_epi32 (stripe_pstns, line_pstns_arr[H], 0);

    final_block |= pws_cnt == pws_cnt_max;
    final_block |= block_start >= src_end;
  }

  // update the source buffer pointer and prepare next pwd index

  if (pws_cnt > pws_cnt_prev)
  {
    // assert ((line_pstns_arr[H] - offset) <= src_end);
    assert ((pws_cnt == pws_cnt_max) || line_pstns_arr[H] == src_end);

    src_buf += line_pstns_arr[H] - offset;

    pws_idx_cur->off = pws_idx_cur[-1].off + pws_idx_cur[-1].cnt; // now ok to throwaway the src buf offset in pws_idx->off
  }

  assert (src_buf <= (indexer_param->buf_limit + 1)); // +1 for sentinel
  assert (pws_cnt <= indexer_param->pws_cnt_max);

  indexer_param->next_line = src_buf;
  indexer_param->pws_cnt   = pws_cnt;

  return words_extra;
}

#endif

indexer_cfg_t get_indexer_cfg (bool fast_mode)
{
  indexer_cfg_t cfg;

  if (fast_mode == true)
  {
    // AVX2 implementation is not supported for MacOS due to clang not supporting function
    // multi-versioning when building for non-ELF targets

    #if defined (__APPLE__)
    cfg.index_lines = &index_lines_fast;
    cfg.align       = IN_BUF_ALIGN_DEFAULT;
    cfg.blk_sz      = IN_BUF_BLOCK_SZ_DEFAULT;

    #else
    bool avx2_supported = (__builtin_cpu_supports ("avx2") > 0)
                       && (__builtin_cpu_supports ("popcnt") > 0)
                       && (__builtin_cpu_supports ("bmi") > 0); // TODO does this reliably detect lzcnt?

    if (avx2_supported == true)
    {
      cfg.index_lines = &index_lines_fast_avx2;
      cfg.align       = IN_BUF_ALIGN_AVX2;
      cfg.blk_sz      = IN_BUF_BLOCK_SZ_AVX2;
    }
    else
    {
      cfg.index_lines = &index_lines_fast;
      cfg.align       = IN_BUF_ALIGN_DEFAULT;
      cfg.blk_sz      = IN_BUF_BLOCK_SZ_DEFAULT;
    }
    #endif
  }
  else
  {
    // non-batched config (default)

    cfg.index_lines = &index_lines_default;
    cfg.align       = IN_BUF_ALIGN_DEFAULT;
    cfg.blk_sz      = IN_BUF_BLOCK_SZ_DEFAULT;
  }

  return cfg;
}

void pw_in_buf_alloc (char **buf, char **alloc, size_t buf_len, u16 align, u16 blk_sz)
{
  *buf = NULL;

  align  = MAX (align, 1);
  blk_sz = MAX (blk_sz, 1);

  if (buf_len > IN_BUF_MAX_SZ)                 return; // requested buffer length too large
  if (power_of_two_ceil_32 (blk_sz) != blk_sz) return; // block-size not a power-of-two
  if (power_of_two_ceil_32 (align) != align)   return; // alignment not a power-of-two

  size_t alloc_sz = buf_len;

  alloc_sz += 1;                                      // allow for prepend sentinel '\n'
  alloc_sz += (align - 1);                            // allow for alignment
  alloc_sz += blk_sz - ((1 + buf_len) & (align - 1)); // allow for last block overrun (also covers append sentinel)

  *alloc = hccalloc (alloc_sz, 1);

  if (*alloc == NULL) return;

  u16 align_offset = (uintptr_t) *alloc & (align - 1); // alignment offset

  u16 buf_offset = 1 + ((align - align_offset) & (align - 1)); // align prepended sentinel

  *buf = *alloc + buf_offset;

  *(*buf - 1) = '\n'; // prepend sentinel
}
