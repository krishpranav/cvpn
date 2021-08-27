#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __SSSE3__
#include <x86intrin.h>
#endif
#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif
#ifdef __linux__
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "charm.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NATIVE_BIG_ENDIAN
#endif
#ifndef NATIVE_BIG_ENDIAN
#ifndef NATIVE_LITTLE_ENDIAN
#define NATIVE_LITTLE_ENDIAN
#endif
#endif

#ifndef XOODOO_ROUNDS
#define XOODOO_ROUNDS 12
#endif

static inline void mem_cpy(unsigned char *dst, const unsigned char *src, size_t n)
{
    size_t i;
    
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static inline void endian_swap_all(uint32_t st[12])
{
    void (st);
    
#ifdef NATIVE_BIG_ENDIAN
    size_t i;
    for (i = 0; i < 12; i++) {
        st[i] = __builtin_bswap32(st[i]);
    }
#endif 
}

void uc_state_init(uint32_t st[12], const unsigned char key[32], const unsigned char iv[16])
{
    memcpy(&st[0], iv, 16);
    memcpy(&st[4], key, 32);
    endian_swap_all(st);
    permute(st);
}

void uc_memzero(void *buf, size_t len)
{
    volatile unsigned char *volatile buf_ = (volatile unsigned char *volatile) buf;
    size_t i                              = (size_t) 0U;

    while (i < len) {
        buf_[i++] = 0U;
    }
}

void uc_randombytes_buf(void *buf, size_t len)
{
#ifdef __linux__
    if ((size_t) syscall(SYS_getrandom, buf, (int) len, 0) != len) {
        abort();
    }
#else
    arc4random_buf(buf, len);
#endif
}
