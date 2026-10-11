/* SM4Kit · C 实现（GB/T 32907-2016）：ECB / CBC + PKCS7 */
#include "sm4.h"
#include <stdlib.h>
#include <string.h>

static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};
static const uint32_t FK[4] = {0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu};

/* ck[i] = 4 字节，每字节 ((4i+j)*7) mod 256 */
static uint32_t ck(int i) {
    return (uint32_t)(((4 * i + 0) * 7) % 256) << 24 | (uint32_t)(((4 * i + 1) * 7) % 256) << 16
         | (uint32_t)(((4 * i + 2) * 7) % 256) << 8 | (uint32_t)(((4 * i + 3) * 7) % 256);
}

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

/* τ：S 盒逐字节代换 */
static uint32_t tau(uint32_t w) {
    return (uint32_t)SBOX[w >> 24] << 24 | (uint32_t)SBOX[(w >> 16) & 255] << 16
         | (uint32_t)SBOX[(w >> 8) & 255] << 8 | (uint32_t)SBOX[w & 255];
}

/* 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24 */
static uint32_t t_enc(uint32_t x) {
    uint32_t b = tau(x);
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
}

/* 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23 */
static uint32_t t_key(uint32_t x) {
    uint32_t b = tau(x);
    return b ^ rotl(b, 13) ^ rotl(b, 23);
}

static uint32_t word(const uint8_t *b, size_t off) {
    return (uint32_t)b[off] << 24 | (uint32_t)b[off + 1] << 16 | (uint32_t)b[off + 2] << 8 | (uint32_t)b[off + 3];
}

static void put_word(uint8_t *out, size_t off, uint32_t w) {
    out[off] = (uint8_t)(w >> 24);
    out[off + 1] = (uint8_t)(w >> 16);
    out[off + 2] = (uint8_t)(w >> 8);
    out[off + 3] = (uint8_t)w;
}

void sm4_round_keys(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t x0 = word(key, 0) ^ FK[0], x1 = word(key, 4) ^ FK[1];
    uint32_t x2 = word(key, 8) ^ FK[2], x3 = word(key, 12) ^ FK[3];
    for (int i = 0; i < 32; i++) {
        uint32_t nx = x0 ^ t_key(x1 ^ x2 ^ x3 ^ ck(i));
        rk[i] = nx;
        x0 = x1; x1 = x2; x2 = x3; x3 = nx;
    }
}

static void crypt_block(const uint32_t rk[32], const uint8_t *src, size_t off, uint8_t *out, size_t ooff) {
    uint32_t x0 = word(src, off), x1 = word(src, off + 4), x2 = word(src, off + 8), x3 = word(src, off + 12);
    for (int i = 0; i < 32; i++) {
        uint32_t nx = x0 ^ t_enc(x1 ^ x2 ^ x3 ^ rk[i]);
        x0 = x1; x1 = x2; x2 = x3; x3 = nx;
    }
    /* 反序变换 R */
    put_word(out, ooff, x3);
    put_word(out, ooff + 4, x2);
    put_word(out, ooff + 8, x1);
    put_word(out, ooff + 12, x0);
}

void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    crypt_block(rk, in, 0, out, 0);
}

void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t rev[32];
    for (int i = 0; i < 32; i++) rev[i] = rk[31 - i];
    crypt_block(rev, in, 0, out, 0);
}

static uint8_t *pad_data(const uint8_t *data, size_t len, size_t *padded_len) {
    size_t n = 16 - len % 16;
    uint8_t *out = (uint8_t *)malloc(len + n);
    if (!out) return NULL;
    memcpy(out, data, len);
    memset(out + len, (int)n, n);
    *padded_len = len + n;
    return out;
}

static int unpad(const uint8_t *data, size_t len, size_t *out_len, const char **err) {
    if (len == 0 || len % 16 != 0) { *err = "非法密文长度"; return 0; }
    uint8_t n = data[len - 1];
    if (n < 1 || n > 16) { *err = "PKCS7 填充校验失败"; return 0; }
    for (size_t i = len - n; i < len; i++)
        if (data[i] != n) { *err = "PKCS7 填充校验失败"; return 0; }
    *out_len = len - n;
    return 1;
}

static uint8_t *ecb_raw(const uint32_t rk[32], const uint8_t *data, size_t len, int decrypt,
                        size_t *out_len, const char **err) {
    if (len % 16 != 0) { *err = "数据长度必须是 16 的倍数"; return NULL; }
    uint8_t *out = (uint8_t *)malloc(len ? len : 1);
    if (!out) { *err = "内存分配失败"; return NULL; }
    uint32_t use_rk[32];
    if (decrypt) {
        for (int i = 0; i < 32; i++) use_rk[i] = rk[31 - i];
        rk = use_rk;
    }
    for (size_t off = 0; off < len; off += 16) crypt_block(rk, data, off, out, off);
    *out_len = len;
    return out;
}

static void xor16(uint8_t *o, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
}

uint8_t *sm4_ecb_encrypt(const uint8_t key[16], const uint8_t *data, size_t len, size_t *out_len, const char **err) {
    *err = NULL;
    uint32_t rk[32];
    sm4_round_keys(key, rk);
    size_t plen;
    uint8_t *padded = pad_data(data, len, &plen);
    if (!padded) { *err = "内存分配失败"; return NULL; }
    uint8_t *out = ecb_raw(rk, padded, plen, 0, out_len, err);
    free(padded);
    return out;
}

uint8_t *sm4_ecb_decrypt(const uint8_t key[16], const uint8_t *data, size_t len, size_t *out_len, const char **err) {
    *err = NULL;
    uint32_t rk[32];
    sm4_round_keys(key, rk);
    size_t raw_len;
    uint8_t *raw = ecb_raw(rk, data, len, 1, &raw_len, err);
    if (!raw) return NULL;
    if (!unpad(raw, raw_len, out_len, err)) { free(raw); return NULL; }
    return raw;
}

uint8_t *sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *data, size_t len,
                         size_t *out_len, const char **err) {
    *err = NULL;
    if (!iv) { *err = "IV 必须为 16 字节"; return NULL; }
    uint32_t rk[32];
    sm4_round_keys(key, rk);
    size_t plen;
    uint8_t *padded = pad_data(data, len, &plen);
    if (!padded) { *err = "内存分配失败"; return NULL; }
    uint8_t *out = (uint8_t *)malloc(plen);
    if (!out) { free(padded); *err = "内存分配失败"; return NULL; }
    uint8_t prev[16], tmp[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < plen; off += 16) {
        xor16(tmp, padded + off, prev);
        crypt_block(rk, tmp, 0, out, off);
        memcpy(prev, out + off, 16);
    }
    free(padded);
    *out_len = plen;
    return out;
}

uint8_t *sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *data, size_t len,
                         size_t *out_len, const char **err) {
    *err = NULL;
    if (!iv) { *err = "IV 必须为 16 字节"; return NULL; }
    if (len == 0 || len % 16 != 0) { *err = "非法密文长度"; return NULL; }
    uint32_t rk[32], rev[32];
    sm4_round_keys(key, rk);
    for (int i = 0; i < 32; i++) rev[i] = rk[31 - i];
    uint8_t *out = (uint8_t *)malloc(len);
    if (!out) { *err = "内存分配失败"; return NULL; }
    uint8_t prev[16], blk[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        crypt_block(rev, data, off, blk, 0);
        xor16(out + off, blk, prev);
        memcpy(prev, data + off, 16);
    }
    if (!unpad(out, len, out_len, err)) { free(out); return NULL; }
    return out;
}
