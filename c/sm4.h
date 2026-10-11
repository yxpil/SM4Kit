/*
 * SM4Kit · C 实现
 * SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，零依赖（仅 stdlib/string）。
 *
 * 编译自测: gcc -O2 -o sm4_test sm4.c test_main.c && ./sm4_test
 */
#ifndef SM4_H
#define SM4_H

#include <stddef.h>
#include <stdint.h>

/* 计算 32 个轮密钥。key：16 字节；rk：输出 32 个 uint32。 */
void sm4_round_keys(const uint8_t key[16], uint32_t rk[32]);

/* 单块加解密（各 16 字节，无填充）。解密用逆序轮密钥。 */
void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]);
void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]);

/* 返回 malloc 分组的密文长度（含 PKCS7 填充），失败返回 0 并置 *err。 */
uint8_t *sm4_ecb_encrypt(const uint8_t key[16], const uint8_t *data, size_t len, size_t *out_len, const char **err);
uint8_t *sm4_ecb_decrypt(const uint8_t key[16], const uint8_t *data, size_t len, size_t *out_len, const char **err);
uint8_t *sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *data, size_t len, size_t *out_len, const char **err);
uint8_t *sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], const uint8_t *data, size_t len, size_t *out_len, const char **err);

#endif
