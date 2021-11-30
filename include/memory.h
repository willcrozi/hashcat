/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MEMORY_H
#define HC_MEMORY_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MSG_ENOMEM "Insufficient memory available"

void *hccalloc                (const size_t nmemb, const size_t sz);
void *hcmalloc                (const size_t sz);
void *hcrealloc               (void *ptr, const size_t oldsz, const size_t addsz);
char *hcstrdup                (const char *s);
void  hcfree                  (void *ptr);

void *hc_alloc_aligned        (size_t alignment, size_t size);
void  hc_free_aligned         (void **ptr);

void *hcmalloc_bridge_aligned (const size_t sz, const int align);
void  hcfree_bridge_aligned   (void *ptr);

// macro to wrap memcpy, optimized to use 16-byte vector writes for smaller copies

// WARNING! when allocating buffers for use with this macro please consider that:
// 1) src read may overrun src by up to 15 bytes, i.e. read up to &src[len + 14]
// 2) dest write may overrun dest by up to 15 bytes, i.e. write up to &dest[len + 14]

#define buf_cpy(dest,src,len)                                                       \
({                                                                                  \
  const uint32_t blk_cnt = ((len) + sizeof (char16) - 1) / sizeof (char16);         \
                                                                                    \
  switch (blk_cnt)                                                                  \
  {                                                                                 \
    default : memcpy ((void *) (dest), (void *) (src), (len)); /* len: 65...  */    \
              break;                                                                \
                                                                                    \
    case 4:   ((char16 *) (dest))[3] = ((char16 *) (src))[3];  /* len: 48..64 */    \
              /* fall-through */                                                    \
    case 3:   ((char16 *) (dest))[2] = ((char16 *) (src))[2];  /* len: 33..48 */    \
              /* fall-through */                                                    \
    case 2:   ((char16 *) (dest))[1] = ((char16 *) (src))[1];  /* len: 17..32 */    \
              /* fall-through */                                                    \
    case 1:   ((char16 *) (dest))[0] = ((char16 *) (src))[0];  /* len:  1..16 */    \
              /* fall-through */                                                    \
    case 0:   break;                                           /* len:  0     */    \
  }                                                                                 \
})

#endif // HC_MEMORY_H
