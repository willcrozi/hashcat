/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <assert.h>

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "backend.h"
#include "wordlist.h"
#include "shared.h"
#include "thread.h"
#include "filehandling.h"
#include "rp.h"
#include "rp_cpu.h"
#include "slow_candidates.h"
#include "stdin.h"
#include "dispatch.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

static u64 get_highest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done > words_cur) words_cur = words_done;
  }

  return words_cur;
}

static u64 get_lowest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0xffffffffffffffff;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (words_cur < status_ctx->words_cur) words_cur = status_ctx->words_cur;

  return words_cur;
}

static int set_kernel_power_final (hashcat_ctx_t *hashcat_ctx, const u64 kernel_power_final)
{
  EVENT (EVENT_SET_KERNEL_POWER_FINAL);

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  backend_ctx->kernel_power_final = kernel_power_final;

  return 0;
}

static u64 get_power (backend_ctx_t *backend_ctx, hc_device_param_t *device_param)
{
  const u64 kernel_power_final = backend_ctx->kernel_power_final;

  if (kernel_power_final)
  {
    const double device_factor = (double) device_param->hardware_power / backend_ctx->hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, device_param->hardware_power);

    // we need to make sure the value is not larger than the regular kernel_power

    const u64 work_final = MIN (work, device_param->kernel_power);

    return work_final;
  }

  return device_param->kernel_power;
}

static u64 get_work (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 max)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const u64 words_off  = status_ctx->words_off;
  const u64 words_base = (user_options->limit == 0) ? status_ctx->words_base : MIN (user_options->limit, status_ctx->words_base);

  device_param->words_off = words_off;

  const u64 kernel_power_all = backend_ctx->kernel_power_all;

  const u64 words_left = words_base - words_off;

  if (words_left < kernel_power_all)
  {
    if (backend_ctx->kernel_power_final == 0)
    {
      set_kernel_power_final (hashcat_ctx, words_left);
    }
  }

  const u64 kernel_power = get_power (backend_ctx, device_param);

  u64 work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  status_ctx->words_off += work;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  return work;
}

// dedicated per-device upload/crack thread related

static void *thread_stdin_crack (void *p); // forward decl

typedef struct crack_ctx
{
  hashcat_ctx_t     *hashcat_ctx;
  hc_device_param_t *device_param;

  bool work;
  bool stop;
  bool err;

  hc_thread_mutex_t mux;
  hc_thread_cond_t  cond;

  hc_thread_t thread;

} crack_ctx_t;

static void crack_ctx_init (crack_ctx_t *crack_ctx, hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  crack_ctx->hashcat_ctx  = hashcat_ctx;
  crack_ctx->device_param = device_param;

  crack_ctx->work = false;
  crack_ctx->stop = false;
  crack_ctx->err  = false;

  hc_thread_mutex_init (crack_ctx->mux);
  hc_thread_cond_init  (&crack_ctx->cond);

  hc_thread_create (crack_ctx->thread, thread_stdin_crack, (void *) crack_ctx);
}

static void crack_ctx_notify_work (crack_ctx_t *crack_ctx)
{
  hc_thread_mutex_lock (crack_ctx->mux);

  crack_ctx->work = true;

  hc_thread_mutex_unlock (crack_ctx->mux);

  hc_thread_cond_notify (&crack_ctx->cond);
}

static void crack_ctx_wait_idle (crack_ctx_t *crack_ctx)
{
  hc_thread_mutex_lock (crack_ctx->mux);

  while (crack_ctx->work == true)
  {
    hc_thread_cond_wait (&crack_ctx->cond, crack_ctx->mux);
  }

  hc_thread_mutex_unlock (crack_ctx->mux);
}

static void crack_ctx_close (crack_ctx_t *crack_ctx, bool quiesce)
{
  hc_thread_mutex_lock (crack_ctx->mux);

  if (quiesce == true)
  {
    while (crack_ctx->work == true)
    {
      hc_thread_cond_wait (&crack_ctx->cond, crack_ctx->mux);
    }
  }

  crack_ctx->stop = true;

  hc_thread_mutex_unlock (crack_ctx->mux);

  hc_thread_cond_notify (&crack_ctx->cond);

  hc_thread_wait (1, &crack_ctx->thread);

  hc_thread_cond_close (&crack_ctx->cond);

  hc_thread_mutex_delete (crack_ctx->mux);
}

static void *thread_stdin_crack (void *p)
{
  crack_ctx_t       *crack_ctx    = (crack_ctx_t *) p;
  hashcat_ctx_t     *hashcat_ctx  = crack_ctx->hashcat_ctx;
  hc_device_param_t *device_param = crack_ctx->device_param;

  hc_thread_mutex_lock (crack_ctx->mux);

  if (device_param->is_cuda == true)
  {
    crack_ctx->err = (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1);

    if (crack_ctx->err == true) goto exit2;
  }

  if (device_param->is_hip == true)
  {
    crack_ctx->err = (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1);

    if (crack_ctx->err == true) goto exit2;
  }

  while (crack_ctx->stop == false)
  {
    while (crack_ctx->work == false)
    {
      if (crack_ctx->stop == true) goto exit1;

      hc_thread_cond_wait (&crack_ctx->cond, crack_ctx->mux);
    }

    if (device_param->pws_cnt == 0) continue;

    hc_thread_mutex_unlock (crack_ctx->mux);

    // flush

    crack_ctx->err = (run_copy (hashcat_ctx, device_param, device_param->pws_cnt) == -1);

    if (crack_ctx->err == false)
    {
      crack_ctx->err = (run_cracker (hashcat_ctx, device_param, -1, device_param->pws_cnt) == -1); // no pws_pos?
    }

    device_param->pws_cnt = 0;

    hc_thread_mutex_lock (crack_ctx->mux);

    crack_ctx->work = false;

    hc_thread_cond_notify (&crack_ctx->cond);

    if (crack_ctx->err == true) break;
  }

  exit1:

  if (device_param->is_cuda == true)
  {
    crack_ctx->err = (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1);
  }

  if (device_param->is_hip == true)
  {
    crack_ctx->err = (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1);
  }

  exit2:

  crack_ctx->work = false; // redundant?

  hc_thread_cond_notify (&crack_ctx->cond);

  hc_thread_mutex_unlock (crack_ctx->mux);

  return NULL;
}

static int calc_stdin (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, stdin_ctx_t *stdin_ctx)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;

  char *in_buf;
  char *in_buf_alloc;

  indexer_cfg_t indexer_cfg = get_indexer_cfg (user_options->stdin_fast);

  index_fn_t index_lines = indexer_cfg.index_lines;

  pw_in_buf_alloc (&in_buf, &in_buf_alloc, STDIN_BUF_SZ, indexer_cfg.align, indexer_cfg.blk_sz);

  if (in_buf == NULL) return -1;

  // setup host post-processing params

  host_proc_param_t host_proc_param;

  host_proc_param.hashcat_ctx   = hashcat_ctx;
  host_proc_param.iconv_enabled = false;
  host_proc_param.iconv_ctx     = NULL;
  host_proc_param.iconv_tmp     = NULL;

  if (attack_mode == ATTACK_MODE_HYBRID2)
  {
    host_proc_param.rule_jk_len = user_options_extra->rule_len_r;
    host_proc_param.rule_jk_buf = user_options->rule_buf_r;
  }
  else
  {
    host_proc_param.rule_jk_len = user_options_extra->rule_len_l;
    host_proc_param.rule_jk_buf = user_options->rule_buf_l;
  }

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    host_proc_param.iconv_enabled = true;

    host_proc_param.iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (host_proc_param.iconv_ctx == (iconv_t) -1)
    {
      hcfree (in_buf_alloc);

      return -1;
    }

    host_proc_param.iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  // setup indexer params

  indexer_param_t indexer_param;

  indexer_param.next_line   = in_buf;
  indexer_param.buf_limit   = in_buf;
  indexer_param.pws_comp    = device_param->pws_comp_b;
  indexer_param.pws_idx     = device_param->pws_idx_b;
  indexer_param.pws_cnt     = 0;
  indexer_param.pws_cnt_max = device_param->kernel_power;
  indexer_param.pw_min      = 0;
  indexer_param.pw_max      = PW_MAX;

  if (attack_kern == ATTACK_KERN_STRAIGHT)
  {
    indexer_param.pw_min    = hashconfig->pw_min;
    indexer_param.pw_max    = hashconfig->pw_max;
  }

  // per device upload/cracking thread setup

  crack_ctx_t crack_ctx;

  crack_ctx_init (&crack_ctx, hashcat_ctx, device_param);

  // stdin reader condvar

  hc_thread_cond_t cond_read;

  hc_thread_cond_init (&cond_read);

  // password input main loop

  bool eof = false;

  while (status_ctx->run_thread_level1 == true)
  {
    if (eof == true) break;

    u64 words_extra_total = 0;

    while (indexer_param.pws_cnt < indexer_param.pws_cnt_max)
    {
      if (status_ctx->run_thread_level1 == false) break;

      if (indexer_param.next_line >= indexer_param.buf_limit)
      {
        stdin_result_t result;

        result = stdin_read (stdin_ctx, in_buf, &cond_read);

        if (result.cnt <= 0)
        {
          if (result.cnt == -1) eof = true;

          break;
        }

        indexer_param.next_line = result.start;
        indexer_param.buf_limit = indexer_param.next_line + result.cnt;
      }

      // index and copy input passwords

      words_extra_total += index_lines (&indexer_param, &host_proc_param);
    }

    if (words_extra_total > 0)
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += words_extra_total * straight_ctx->kernel_rules_cnt;
      }

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }

    if (status_ctx->run_thread_level1 == false) break;

    crack_ctx_wait_idle (&crack_ctx);

    if (crack_ctx.err == true) break;

    if (status_ctx->run_thread_level1 == false) break;

    if (device_param->speed_only_finish == true) break;

    if (indexer_param.pws_cnt == 0) continue;

    // flip/reset host password buffers

    u32      *pws_comp_tmp = device_param->pws_comp;
    pw_idx_t *pws_idx_tmp  = device_param->pws_idx;

    device_param->pws_comp = indexer_param.pws_comp;
    device_param->pws_idx  = indexer_param.pws_idx;
    device_param->pws_cnt  = indexer_param.pws_cnt;

    indexer_param.pws_comp = pws_comp_tmp;
    indexer_param.pws_idx  = pws_idx_tmp;
    indexer_param.pws_cnt  = 0;

    // notify crack-thread of new work

    crack_ctx_notify_work (&crack_ctx);
  }

  crack_ctx_close (&crack_ctx, status_ctx->run_thread_level1);

  device_param->pws_comp_b = indexer_param.pws_comp;
  device_param->pws_idx_b  = indexer_param.pws_idx;

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;

  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  if (host_proc_param.iconv_enabled == true)
  {
    iconv_close (host_proc_param.iconv_ctx);

    hcfree (host_proc_param.iconv_tmp);
  }

  hcfree (in_buf_alloc);

  if (crack_ctx.err == true) return -1;

  return 0;
}

HC_API_CALL void *thread_calc_stdin (void *p)
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  stdin_ctx_t   *stdin_ctx   = thread_param->stdin_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return NULL;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped) return NULL;
  if (device_param->skipped_warning == true) return NULL;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (bridge_ctx->platform_context, device_param, hashconfig, hashes) == false) return NULL;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return NULL;
  }

  if (calc_stdin (hashcat_ctx, device_param, stdin_ctx) == -1)
  {
    status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

    status_ctx->devices_status = STATUS_ERROR;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return NULL;
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  return NULL;
}

static int calc (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;

  if (user_options->slow_candidates == true)
  {
    #ifdef WITH_BRAIN
    const u32 brain_session = user_options->brain_session;
    const u32 brain_attack  = user_options->brain_attack;

    u64 highest = 0;

    brain_client_disconnect (device_param);

    if (user_options->brain_client == true)
    {
      const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

      if (brain_client_connect (device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, brain_session, brain_attack, passwords_max, &highest) == false)
      {
        brain_client_disconnect (device_param);
      }

      if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
      {
        hc_thread_mutex_lock (status_ctx->mux_dispatcher);

        if (status_ctx->words_off == 0)
        {
          status_ctx->words_off = highest;

          for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
          {
            status_ctx->words_progress_rejected[salt_pos] = status_ctx->words_off;
          }
        }

        hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
      }
    }
    #endif

    // attack modes from here

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      char *dictfile = straight_ctx->dict;

      extra_info_straight_t extra_info_straight;

      memset (&extra_info_straight, 0, sizeof (extra_info_straight));

      if (hc_fopen (&extra_info_straight.fp, dictfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

        return -1;
      }

      hashcat_ctx_t *hashcat_ctx_tmp = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

      memcpy (hashcat_ctx_tmp, hashcat_ctx, sizeof (hashcat_ctx_t)); // yes we actually want to copy these pointers

      hashcat_ctx_tmp->wl_data = (wl_data_t *) hcmalloc (sizeof (wl_data_t));

      if (wl_data_init (hashcat_ctx_tmp) == -1)
      {
        hc_fclose (&extra_info_straight.fp);

        hcfree (hashcat_ctx_tmp->wl_data);

        hcfree (hashcat_ctx_tmp);

        return -1;
      }

      u64 words_cur = 0;

      while (status_ctx->run_thread_level1 == true)
      {
        u64 words_fin = 0;

        memset (device_param->pws_comp,     0, device_param->size_pws_comp);
        memset (device_param->pws_idx,      0, device_param->size_pws_idx);
        memset (device_param->pws_base_buf, 0, device_param->size_pws_base);

        u64 pre_rejects = -1;

        // this greatly reduces spam on hashcat console

        const u64 pre_rejects_ignore = get_power (backend_ctx, device_param) / 2;

        while (pre_rejects > pre_rejects_ignore)
        {
          u64 words_extra_total = 0;

          u64 words_extra = pre_rejects;

          pre_rejects = 0;

          memset (device_param->pws_pre_buf, 0, device_param->size_pws_pre);

          device_param->pws_pre_cnt = 0;

          while (words_extra)
          {
            u64 work = get_work (hashcat_ctx, device_param, words_extra);

            if (work == 0) break;

            u64 words_off = device_param->words_off;

            #ifdef WITH_BRAIN
            if (user_options->brain_client == true)
            {
              if (device_param->brain_link_client_fd == -1)
              {
                const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

                if (brain_client_connect (device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session, user_options->brain_attack, passwords_max, &highest) == false)
                {
                  brain_client_disconnect (device_param);
                }
              }

              if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
              {
                u64 overlap = 0;

                if (brain_client_reserve (device_param, status_ctx, words_off, work, &overlap) == false)
                {
                  brain_client_disconnect (device_param);
                }

                words_extra        = overlap;
                words_extra_total += overlap;
                words_off         += overlap;
                work              -= overlap;
              }
            }
            #endif

            words_fin = words_off + work;

            words_extra = 0;

            slow_candidates_seek (hashcat_ctx_tmp, &extra_info_straight, words_cur, words_off);

            words_cur = words_off;

            for (u64 i = words_cur; i < words_fin; i++)
            {
              extra_info_straight.pos = i;

              slow_candidates_next (hashcat_ctx_tmp, &extra_info_straight);

              if ((extra_info_straight.out_len < hashconfig->pw_min) || (extra_info_straight.out_len > hashconfig->pw_max))
              {
                pre_rejects++;

                continue;
              }

              #ifdef WITH_BRAIN
              if (user_options->brain_client == true)
              {
                u32 hash[2];

                brain_client_generate_hash ((u64 *) hash, (const char *) extra_info_straight.out_buf, extra_info_straight.out_len);

                u32 *ptr = device_param->brain_link_out_buf;

                ptr[(device_param->pws_pre_cnt * 2) + 0] = hash[0];
                ptr[(device_param->pws_pre_cnt * 2) + 1] = hash[1];
              }
              #endif

              pw_pre_add (device_param, extra_info_straight.out_buf, extra_info_straight.out_len, extra_info_straight.base_buf, extra_info_straight.base_len, extra_info_straight.rule_pos_prev);

              if (status_ctx->run_thread_level1 == false) break;
            }

            words_cur = words_fin;

            words_extra_total += words_extra;

            if (status_ctx->run_thread_level1 == false) break;
          }

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_HASHES)
            {
              if (brain_client_lookup (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }

            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              if (device_param->brain_link_in_buf[pws_pre_idx] == 1)
              {
                pre_rejects++;
              }
              else
              {
                pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

                pw_base_add (device_param, pw_pre);

                pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
              }
            }
          }
          else
          {
            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

              pw_base_add (device_param, pw_pre);

              pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
            }
          }
          #else
          u64 pws_pre_cnt = device_param->pws_pre_cnt;

          for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
          {
            pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

            pw_base_add (device_param, pw_pre);

            pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
          }
          #endif

          words_extra_total += pre_rejects;

          if (status_ctx->run_thread_level1 == false) break;

          if (words_extra_total > 0)
          {
            hc_thread_mutex_lock (status_ctx->mux_counter);

            for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
            {
              status_ctx->words_progress_rejected[salt_pos] += words_extra_total;
            }

            hc_thread_mutex_unlock (status_ctx->mux_counter);
          }
        }

        //
        // flush
        //

        const u64 pws_cnt = device_param->pws_cnt;

        if (pws_cnt)
        {
          if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1)
          {
            hc_fclose (&extra_info_straight.fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          if (run_cracker (hashcat_ctx, device_param, -1, pws_cnt) == -1)
          {
            hc_fclose (&extra_info_straight.fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if ((status_ctx->devices_status != STATUS_ABORTED)
             && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
             && (status_ctx->devices_status != STATUS_QUIT)
             && (status_ctx->devices_status != STATUS_BYPASS)
             && (status_ctx->devices_status != STATUS_ERROR))
            {
              if (brain_client_commit (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }
          }
          #endif

          device_param->pws_cnt      = 0;
          device_param->pws_base_cnt = 0;
        }

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_highest_words_done (hashcat_ctx);
        }

        if (status_ctx->run_thread_level1 == false) break;

        if (words_fin == 0) break;
      }

      hc_fclose (&extra_info_straight.fp);

      wl_data_destroy (hashcat_ctx_tmp);

      hcfree (hashcat_ctx_tmp->wl_data);
      hcfree (hashcat_ctx_tmp);
    }
    else if (attack_mode == ATTACK_MODE_COMBI)
    {
      const u32 combs_mode = combinator_ctx->combs_mode;

      char *base_file;
      char *combs_file;

      if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
      {
        base_file  = combinator_ctx->dict1;
        combs_file = combinator_ctx->dict2;
      }
      else
      {
        base_file  = combinator_ctx->dict2;
        combs_file = combinator_ctx->dict1;
      }

      extra_info_combi_t extra_info_combi;

      memset (&extra_info_combi, 0, sizeof (extra_info_combi));

      if (hc_fopen (&extra_info_combi.base_fp, base_file, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", base_file, strerror (errno));

        return -1;
      }

      if (hc_fopen (&extra_info_combi.combs_fp, combs_file, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", combs_file, strerror (errno));

        hc_fclose (&extra_info_combi.base_fp);

        return -1;
      }

      extra_info_combi.scratch_buf = device_param->scratch_buf;

      hashcat_ctx_t *hashcat_ctx_tmp = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

      memcpy (hashcat_ctx_tmp, hashcat_ctx, sizeof (hashcat_ctx_t)); // yes we actually want to copy these pointers

      hashcat_ctx_tmp->wl_data = (wl_data_t *) hcmalloc (sizeof (wl_data_t));

      if (wl_data_init (hashcat_ctx_tmp) == -1)
      {
        hc_fclose (&extra_info_combi.base_fp);
        hc_fclose (&extra_info_combi.combs_fp);

        hcfree (hashcat_ctx_tmp->wl_data);
        hcfree (hashcat_ctx_tmp);

        return -1;
      }

      u64 words_cur = 0;

      while (status_ctx->run_thread_level1 == true)
      {
        u64 words_fin = 0;

        memset (device_param->pws_comp,     0, device_param->size_pws_comp);
        memset (device_param->pws_idx,      0, device_param->size_pws_idx);
        memset (device_param->pws_base_buf, 0, device_param->size_pws_base);

        u64 pre_rejects = -1;

        // this greatly reduces spam on hashcat console

        const u64 pre_rejects_ignore = get_power (backend_ctx, device_param) / 2;

        while (pre_rejects > pre_rejects_ignore)
        {
          u64 words_extra_total = 0;

          u64 words_extra = pre_rejects;

          pre_rejects = 0;

          memset (device_param->pws_pre_buf, 0, device_param->size_pws_pre);

          device_param->pws_pre_cnt = 0;

          while (words_extra)
          {
            u64 work = get_work (hashcat_ctx, device_param, words_extra);

            if (work == 0) break;

            words_extra = 0;

            u64 words_off = device_param->words_off;

            #ifdef WITH_BRAIN
            if (user_options->brain_client == true)
            {
              if (device_param->brain_link_client_fd == -1)
              {
                const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

                if (brain_client_connect (device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session, user_options->brain_attack, passwords_max, &highest) == false)
                {
                  brain_client_disconnect (device_param);
                }
              }

              if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
              {
                u64 overlap = 0;

                if (brain_client_reserve (device_param, status_ctx, words_off, work, &overlap) == false)
                {
                  brain_client_disconnect (device_param);
                }

                words_extra        = overlap;
                words_extra_total += overlap;
                words_off         += overlap;
                work              -= overlap;
              }
            }
            #endif

            words_fin = words_off + work;

            slow_candidates_seek (hashcat_ctx_tmp, &extra_info_combi, words_cur, words_off);

            words_cur = words_off;

            for (u64 i = words_cur; i < words_fin; i++)
            {
              extra_info_combi.pos = i;

              slow_candidates_next (hashcat_ctx_tmp, &extra_info_combi);

              if ((extra_info_combi.out_len < hashconfig->pw_min) || (extra_info_combi.out_len > hashconfig->pw_max))
              {
                pre_rejects++;

                continue;
              }

              #ifdef WITH_BRAIN
              if (user_options->brain_client == true)
              {
                u32 hash[2];

                brain_client_generate_hash ((u64 *) hash, (const char *) extra_info_combi.out_buf, extra_info_combi.out_len);

                u32 *ptr = device_param->brain_link_out_buf;

                ptr[(device_param->pws_pre_cnt * 2) + 0] = hash[0];
                ptr[(device_param->pws_pre_cnt * 2) + 1] = hash[1];
              }
              #endif

              pw_pre_add (device_param, extra_info_combi.out_buf, extra_info_combi.out_len, NULL, 0, 0);

              if (status_ctx->run_thread_level1 == false) break;
            }

            words_cur = words_fin;

            words_extra_total += words_extra;

            if (status_ctx->run_thread_level1 == false) break;
          }

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_HASHES)
            {
              if (brain_client_lookup (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }

            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              if (device_param->brain_link_in_buf[pws_pre_idx] == 1)
              {
                pre_rejects++;
              }
              else
              {
                pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

                pw_base_add (device_param, pw_pre);

                pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
              }
            }
          }
          else
          {
            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

              pw_base_add (device_param, pw_pre);

              pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
            }
          }
          #else
          u64 pws_pre_cnt = device_param->pws_pre_cnt;

          for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
          {
            pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

            pw_base_add (device_param, pw_pre);

            pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
          }
          #endif

          words_extra_total += pre_rejects;

          if (status_ctx->run_thread_level1 == false) break;

          if (words_extra_total > 0)
          {
            hc_thread_mutex_lock (status_ctx->mux_counter);

            for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
            {
              status_ctx->words_progress_rejected[salt_pos] += words_extra_total;
            }

            hc_thread_mutex_unlock (status_ctx->mux_counter);
          }
        }

        //
        // flush
        //

        const u64 pws_cnt = device_param->pws_cnt;

        if (pws_cnt)
        {
          if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1)
          {
            hc_fclose (&extra_info_combi.base_fp);
            hc_fclose (&extra_info_combi.combs_fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          if (run_cracker (hashcat_ctx, device_param, -1, pws_cnt) == -1)
          {
            hc_fclose (&extra_info_combi.base_fp);
            hc_fclose (&extra_info_combi.combs_fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if ((status_ctx->devices_status != STATUS_ABORTED)
             && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
             && (status_ctx->devices_status != STATUS_QUIT)
             && (status_ctx->devices_status != STATUS_BYPASS)
             && (status_ctx->devices_status != STATUS_ERROR))
            {
              if (brain_client_commit (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }
          }
          #endif

          device_param->pws_cnt      = 0;
          device_param->pws_base_cnt = 0;
        }

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_highest_words_done (hashcat_ctx);
        }

        if (status_ctx->run_thread_level1 == false) break;

        if (words_fin == 0) break;
      }

      hc_fclose (&extra_info_combi.base_fp);
      hc_fclose (&extra_info_combi.combs_fp);

      wl_data_destroy (hashcat_ctx_tmp);

      hcfree (hashcat_ctx_tmp->wl_data);
      hcfree (hashcat_ctx_tmp);
    }
    else if (attack_mode == ATTACK_MODE_BF)
    {
      extra_info_mask_t extra_info_mask;

      memset (&extra_info_mask, 0, sizeof (extra_info_mask));

      extra_info_mask.out_len = mask_ctx->css_cnt;

      u64 words_cur = 0;

      while (status_ctx->run_thread_level1 == true)
      {
        u64 words_fin = 0;

        memset (device_param->pws_comp, 0, device_param->size_pws_comp);
        memset (device_param->pws_idx,  0, device_param->size_pws_idx);

        u64 pre_rejects = -1;

        // this greatly reduces spam on hashcat console

        const u64 pre_rejects_ignore = get_power (backend_ctx, device_param) / 2;

        while (pre_rejects > pre_rejects_ignore)
        {
          u64 words_extra_total = 0;

          u64 words_extra = pre_rejects;

          pre_rejects = 0;

          memset (device_param->pws_pre_buf, 0, device_param->size_pws_pre);

          device_param->pws_pre_cnt = 0;

          while (words_extra)
          {
            u64 work = get_work (hashcat_ctx, device_param, words_extra);

            if (work == 0) break;

            words_extra = 0;

            u64 words_off = device_param->words_off;

            #ifdef WITH_BRAIN
            if (user_options->brain_client == true)
            {
              if (device_param->brain_link_client_fd == -1)
              {
                const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

                if (brain_client_connect (device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session, user_options->brain_attack, passwords_max, &highest) == false)
                {
                  brain_client_disconnect (device_param);
                }
              }

              if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
              {
                u64 overlap = 0;

                if (brain_client_reserve (device_param, status_ctx, words_off, work, &overlap) == false)
                {
                  brain_client_disconnect (device_param);
                }

                words_extra        = overlap;
                words_extra_total += overlap;
                words_off         += overlap;
                work              -= overlap;
              }
            }
            #endif

            words_fin = words_off + work;
            words_cur = words_off;

            for (u64 i = words_cur; i < words_fin; i++)
            {
              extra_info_mask.pos = i;

              slow_candidates_next (hashcat_ctx, &extra_info_mask);

              #ifdef WITH_BRAIN
              if (user_options->brain_client == true)
              {
                u32 hash[2];

                brain_client_generate_hash ((u64 *) hash, (const char *) extra_info_mask.out_buf, extra_info_mask.out_len);

                u32 *ptr = device_param->brain_link_out_buf;

                ptr[(device_param->pws_pre_cnt * 2) + 0] = hash[0];
                ptr[(device_param->pws_pre_cnt * 2) + 1] = hash[1];
              }
              #endif

              pw_pre_add (device_param, extra_info_mask.out_buf, extra_info_mask.out_len, NULL, 0, 0);

              if (status_ctx->run_thread_level1 == false) break;
            }

            words_cur = words_fin;

            words_extra_total += words_extra;

            if (status_ctx->run_thread_level1 == false) break;
          }

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_HASHES)
            {
              if (brain_client_lookup (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }

            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              if (device_param->brain_link_in_buf[pws_pre_idx] == 1)
              {
                pre_rejects++;
              }
              else
              {
                pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

                pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
              }
            }
          }
          else
          {
            u64 pws_pre_cnt = device_param->pws_pre_cnt;

            for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
            {
              pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

              pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
            }
          }
          #else
          u64 pws_pre_cnt = device_param->pws_pre_cnt;

          for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
          {
            pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

            pw_add (device_param, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
          }
          #endif

          words_extra_total += pre_rejects;

          if (status_ctx->run_thread_level1 == false) break;

          if (words_extra_total > 0)
          {
            hc_thread_mutex_lock (status_ctx->mux_counter);

            for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
            {
              status_ctx->words_progress_rejected[salt_pos] += words_extra_total;
            }

            hc_thread_mutex_unlock (status_ctx->mux_counter);
          }
        }

        //
        // flush
        //

        const u64 pws_cnt = device_param->pws_cnt;

        if (pws_cnt)
        {
          if (run_copy    (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
          if (run_cracker (hashcat_ctx, device_param, -1, pws_cnt) == -1) return -1;

          #ifdef WITH_BRAIN
          if (user_options->brain_client == true)
          {
            if ((status_ctx->devices_status != STATUS_ABORTED)
             && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
             && (status_ctx->devices_status != STATUS_QUIT)
             && (status_ctx->devices_status != STATUS_BYPASS)
             && (status_ctx->devices_status != STATUS_ERROR))
            {
              if (brain_client_commit (device_param, status_ctx) == false)
              {
                brain_client_disconnect (device_param);
              }
            }
          }
          #endif

          device_param->pws_cnt = 0;
        }

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_highest_words_done (hashcat_ctx);
        }

        if (status_ctx->run_thread_level1 == false) break;

        if (words_fin == 0) break;
      }
    }

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      brain_client_disconnect (device_param);
    }
    #endif
  }
  else
  {
    if ((attack_mode == ATTACK_MODE_BF) || (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (attack_mode == ATTACK_MODE_HYBRID2)))
    {
      if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (attack_mode == ATTACK_MODE_HYBRID2))
      {
        char *dictfile = straight_ctx->dict;

        if (hc_fopen (&device_param->combs_fp, dictfile, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

          return -1;
        }
      }

      while (status_ctx->run_thread_level1 == true)
      {
        const u64 work = get_work (hashcat_ctx, device_param, -1);

        if (work == 0) break;

        const u64 words_off = device_param->words_off;
        const u64 words_fin = words_off + work;

        device_param->pws_cnt = work;

        if (run_copy    (hashcat_ctx, device_param, device_param->pws_cnt) == -1) return -1;
        if (run_cracker (hashcat_ctx, device_param, -1, device_param->pws_cnt) == -1) return -1;

        device_param->pws_cnt = 0;

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_lowest_words_done (hashcat_ctx);
        }
      }
    }
    else
    {
      char *dictfile = straight_ctx->dict;

      if (attack_mode == ATTACK_MODE_COMBI)
      {
        if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          dictfile = combinator_ctx->dict1;
        }
        else
        {
          dictfile = combinator_ctx->dict2;
        }

        const u32 combs_mode = combinator_ctx->combs_mode;

        if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          const char *dictfilec = combinator_ctx->dict2;

          if (hc_fopen (&device_param->combs_fp, dictfilec, "rb") == false)
          {
            event_log_error (hashcat_ctx, "%s: %s", combinator_ctx->dict2, strerror (errno));

            return -1;
          }
        }
        else if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
        {
          const char *dictfilec = combinator_ctx->dict1;

          if (hc_fopen (&device_param->combs_fp, dictfilec, "rb") == false)
          {
            event_log_error (hashcat_ctx, "%s: %s", dictfilec, strerror (errno));

            return -1;
          }
        }
      }

      HCFILE fp;

      if (hc_fopen (&fp, dictfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

        return -1;
      }

      hashcat_ctx_t *hashcat_ctx_tmp = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

      memcpy (hashcat_ctx_tmp, hashcat_ctx, sizeof (hashcat_ctx_t)); // yes we actually want to copy these pointers

      hashcat_ctx_tmp->wl_data = (wl_data_t *) hcmalloc (sizeof (wl_data_t));

      if (wl_data_init (hashcat_ctx_tmp) == -1)
      {
        if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

        hc_fclose (&fp);

        hcfree (hashcat_ctx_tmp->wl_data);
        hcfree (hashcat_ctx_tmp);

        return -1;
      }

      u64 words_cur = 0;

      while (status_ctx->run_thread_level1 == true)
      {
        u64 words_off = 0;
        u64 words_fin = 0;
        u64 words_extra = -1U;
        u64 words_extra_total = 0;

        memset (device_param->pws_comp, 0, device_param->size_pws_comp);
        memset (device_param->pws_idx,  0, device_param->size_pws_idx);

        while (words_extra)
        {
          const u64 work = get_work (hashcat_ctx, device_param, words_extra);

          if (work == 0) break;

          words_extra = 0;

          words_off = device_param->words_off;
          words_fin = words_off + work;

          char *line_buf;
          u32   line_len;

          char rule_buf_out[RP_PASSWORD_SIZE];

          for ( ; words_cur < words_off; words_cur++) get_next_word (hashcat_ctx_tmp, &fp, &line_buf, &line_len);

          for ( ; words_cur < words_fin; words_cur++)
          {
            get_next_word (hashcat_ctx_tmp, &fp, &line_buf, &line_len);

            // post-process rule engine

            int   rule_jk_len = (int)    user_options_extra->rule_len_l;
            const char *rule_jk_buf = user_options->rule_buf_l;

            if (attack_mode == ATTACK_MODE_HYBRID2)
            {
              rule_jk_len = (int)    user_options_extra->rule_len_r;
              rule_jk_buf = user_options->rule_buf_r;
            }

            if (run_rule_engine (rule_jk_len, rule_jk_buf))
            {
              if (line_len >= RP_PASSWORD_SIZE) continue;

              memset (rule_buf_out, 0, sizeof (rule_buf_out));

              const int rule_len_out = _old_apply_rule (rule_jk_buf, rule_jk_len, line_buf, (int) line_len, rule_buf_out);

              if (rule_len_out < 0) continue;

              line_buf = rule_buf_out;
              line_len = (u32) rule_len_out;
            }

            /*

            if (attack_mode == ATTACK_MODE_ASSOCIATION)
            {
              // we can't reject password base on length in -a 9 because it will bring the schedule out of sync
              // therefore we render it defective so the other candidates survive

              line_len = MAX (line_len, hashconfig->pw_min);
              line_len = MIN (line_len, hashconfig->pw_max);
            }

            This strategy turns out not to work very well. If there's a candidate shorter than pw_min, this leads to situation the \n is copied, too.

            To reproduce:

            $ cat hash
            WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***
            $ cat word
            hashcat
            $ ./hashcat -m 22000 -a 9 hash word
            ...
            Candidates.#1....: $HEX[686173686361740a21] -> $HEX[686173686361740a21]
            ...
            */

            // This is a test fix for the above situation

            if (attack_kern == ATTACK_KERN_STRAIGHT)
            {
              if (attack_mode == ATTACK_MODE_ASSOCIATION)
              {
                // do nothing, test fix for above scenario
              }
              else
              {
                if ((line_len < hashconfig->pw_min) || (line_len > hashconfig->pw_max))
                {
                  words_extra++;

                  continue;
                }
              }
            }
            else if (attack_kern == ATTACK_KERN_COMBI)
            {
              // do not check if minimum restriction is satisfied (line_len >= hashconfig->pw_min) here
              // since we still need to combine the plains

              if (line_len > hashconfig->pw_max)
              {
                words_extra++;

                continue;
              }
            }

            pw_add (device_param, (const u8 *) line_buf, (const int) line_len);

            if (status_ctx->run_thread_level1 == false) break;
          }

          words_extra_total += words_extra;

          if (status_ctx->run_thread_level1 == false) break;
        }

        if (status_ctx->run_thread_level1 == false) break;

        if (words_extra_total > 0)
        {
          hc_thread_mutex_lock (status_ctx->mux_counter);

          for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
          {
            if (attack_kern == ATTACK_KERN_STRAIGHT)
            {
              status_ctx->words_progress_rejected[salt_pos] += words_extra_total * straight_ctx->kernel_rules_cnt;
            }
            else if (attack_kern == ATTACK_KERN_COMBI)
            {
              status_ctx->words_progress_rejected[salt_pos] += words_extra_total * combinator_ctx->combs_cnt;
            }
          }

          hc_thread_mutex_unlock (status_ctx->mux_counter);
        }

        //
        // flush
        //

        const u64 pws_cnt = device_param->pws_cnt;

        if (pws_cnt)
        {
          if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1)
          {
            if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

            hc_fclose (&fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          if (run_cracker (hashcat_ctx, device_param, device_param->words_off, pws_cnt) == -1)
          {
            if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

            hc_fclose (&fp);

            hcfree (hashcat_ctx_tmp->wl_data);
            hcfree (hashcat_ctx_tmp);

            return -1;
          }

          device_param->pws_cnt = 0;

          /*
          still required?
          if (attack_kern == ATTACK_KERN_STRAIGHT)
          {
            CL_rc = run_kernel_bzero (device_param, device_param->d_rules_c, device_param->size_rules_c);
            if (CL_rc == -1)
            {
              if (attack_mode == ATTACK_MODE_COMBI) fclose (device_param->combs_fp);
              fclose (fd);
              hcfree (hashcat_ctx_tmp->wl_data);
              hcfree (hashcat_ctx_tmp);
              return -1;
            }
          }
          else if (attack_kern == ATTACK_KERN_COMBI)
          {
            CL_rc = run_kernel_bzero (device_param, device_param->d_combs_c, device_param->size_combs);
            if (CL_rc == -1)
            {
              if (attack_mode == ATTACK_MODE_COMBI) fclose (device_param->combs_fp);
              fclose (fd);
              hcfree (hashcat_ctx_tmp->wl_data);
              hcfree (hashcat_ctx_tmp);
              return -1;
            }
          }
          */
        }

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_lowest_words_done (hashcat_ctx);
        }

        if (status_ctx->run_thread_level1 == false) break;

        if (words_fin == 0) break;
      }

      if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

      hc_fclose (&fp);

      wl_data_destroy (hashcat_ctx_tmp);

      hcfree (hashcat_ctx_tmp->wl_data);
      hcfree (hashcat_ctx_tmp);
    }
  }

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;

  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  return 0;
}

HC_API_CALL void *thread_calc (void *p)
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return NULL;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped) return NULL;
  if (device_param->skipped_warning == true) return NULL;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (bridge_ctx->platform_context, device_param, hashconfig, hashes) == false) return NULL;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return NULL;
  }

  if (calc (hashcat_ctx, device_param) == -1)
  {
    status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

    status_ctx->devices_status = STATUS_ERROR;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return NULL;
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  return NULL;
}
