/*
 * SM4Kit · C 自测程序
 * 编译: gcc -O2 -o sm4_test sm4.c test_main.c && ./sm4_test [--long]
 */
#include "sm4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void unhex(const char *s, uint8_t *out) {
    for (size_t i = 0; i < strlen(s) / 2; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int test_cb(const char *name, int ok, const uint8_t *got, size_t got_len) {
    printf("%s: %s", name, ok ? "PASS" : "FAIL");
    if (got) {
        printf(" got=");
        for (size_t i = 0; i < got_len; i++) printf("%02x", got[i]);
    }
    printf("\n");
    return ok;
}

int main(int argc, char **argv) {
    int ok = 1;
    uint8_t key[16], pt[16];
    unhex("0123456789abcdeffedcba9876543210", key);
    unhex("0123456789abcdeffedcba9876543210", pt);

    /* KAT1：GB/T 32907-2016 附录A 示例1（首块） */
    size_t ct_len;
    const char *err = NULL;
    uint8_t *ct = sm4_ecb_encrypt(key, pt, 16, &ct_len, &err);
    if (!ct) { printf("ecb_encrypt error: %s\n", err); return 1; }
    {
        const char *want = "\x68\x1e\xdf\x34\xd2\x06\x96\x5e\x86\xb3\xe9\x4f\x53\x6e\x42\x46";
        int good = ct_len >= 16 && memcmp(ct, want, 16) == 0;
        ok &= test_cb("KAT1 ecb", good, ct, 16);
    }
    /* 往返 */
    {
        size_t rt_len;
        uint8_t *rt = sm4_ecb_decrypt(key, ct, ct_len, &rt_len, &err);
        int good = rt && rt_len == 16 && memcmp(rt, pt, 16) == 0;
        ok &= test_cb("KAT  ecb-roundtrip", good, NULL, 0);
        free(rt);
    }
    free(ct);

    /* 边界往返（0/1/15/16/17/100 字节，LCG 生成确定性数据） */
    {
        unsigned long lcg = 12345;
        size_t sizes[] = {0, 1, 15, 16, 17, 100};
        int all_ok = 1;
        for (int t = 0; t < 6; t++) {
            size_t n = sizes[t];
            uint8_t data[128], iv[16], k[16];
            for (size_t i = 0; i < n; i++) { lcg = lcg * 1103515245 + 12345; data[i] = (uint8_t)(lcg >> 16); }
            for (int i = 0; i < 16; i++) { lcg = lcg * 1103515245 + 12345; k[i] = (uint8_t)(lcg >> 16); }
            for (int i = 0; i < 16; i++) { lcg = lcg * 1103515245 + 12345; iv[i] = (uint8_t)(lcg >> 16); }
            size_t e_len;
            uint8_t *enc = sm4_cbc_encrypt(k, iv, data, n, &e_len, &err);
            if (!enc) { all_ok = 0; break; }
            size_t d_len;
            uint8_t *dec = sm4_cbc_decrypt(k, iv, enc, e_len, &d_len, &err);
            if (!dec || d_len != n || (n && memcmp(dec, data, n) != 0)) all_ok = 0;
            free(enc);
            free(dec);
            if (!all_ok) break;
        }
        ok &= test_cb("EDGE cbc-roundtrip", all_ok, NULL, 0);
    }

    /* CBC 链式验证 */
    {
        uint8_t iv[16];
        unhex("fedcba98765432100123456789abcdef", iv);
        size_t ct_len2, ref_len;
        uint8_t *ct2 = sm4_cbc_encrypt(key, iv, pt, 16, &ct_len2, &err);
        uint8_t x[16];
        for (int i = 0; i < 16; i++) x[i] = (uint8_t)(pt[i] ^ iv[i]);
        uint8_t *ref = sm4_ecb_encrypt(key, x, 16, &ref_len, &err);
        int good = ct2 && ref && memcmp(ct2, ref, 16) == 0;
        ok &= test_cb("KAT  cbc-chain", good, NULL, 0);
        free(ct2);
        free(ref);
    }

    /* 100 万次迭代向量（GB/T 32907 示例2）——默认跳过，--long 启用 */
    if (argc > 1 && strcmp(argv[1], "--long") == 0) {
        uint32_t rk[32];
        sm4_round_keys(key, rk);
        uint8_t x[16];
        memcpy(x, pt, 16);
        for (long i = 0; i < 1000000; i++) sm4_encrypt_block(rk, x, x);
        const char *want = "\x59\x52\x98\xc7\xc6\xfd\x27\x1f\x04\x02\xf8\x04\xc3\x3d\x3f\x66";
        int good = memcmp(x, want, 16) == 0;
        ok &= test_cb("KAT2 1M-iterations", good, x, 16);
    }

    printf("ALL %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
