# -*- coding: utf-8 -*-
"""
SM4Kit · Python 实现
SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，纯标准库、零依赖。

用法：
    from sm4_kit import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
    ct = cbc_encrypt(key16, iv16, b"hello")
    pt = cbc_decrypt(key16, iv16, ct)

自测：python sm4_kit.py          # 快速向量
     python sm4_kit.py --long   # 附加 100 万次迭代向量（较慢）
"""

import sys

SBOX = [
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
]
FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
# CK[i] = 4 字节，每字节 ((4i+j)*7) mod 256
CK = tuple(
    ((4 * i + 0) * 7 % 256) << 24 | ((4 * i + 1) * 7 % 256) << 16
    | ((4 * i + 2) * 7 % 256) << 8 | ((4 * i + 3) * 7 % 256)
    for i in range(32)
)
_M = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _M


def _tau(w):
    return (SBOX[(w >> 24) & 255] << 24 | SBOX[(w >> 16) & 255] << 16
            | SBOX[(w >> 8) & 255] << 8 | SBOX[w & 255]) & _M


def _t_enc(x):
    b = _tau(x)
    return (b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)) & _M


def _t_key(x):
    b = _tau(x)
    return (b ^ _rotl(b, 13) ^ _rotl(b, 23)) & _M


def _word(buf, off):
    return (buf[off] << 24 | buf[off + 1] << 16 | buf[off + 2] << 8 | buf[off + 3]) & _M


def _put_word(out, off, w):
    out[off] = (w >> 24) & 255
    out[off + 1] = (w >> 16) & 255
    out[off + 2] = (w >> 8) & 255
    out[off + 3] = w & 255


def round_keys(key):
    """32 个轮密钥。key：16 字节 bytes/bytearray。"""
    if len(key) != 16:
        raise ValueError("SM4 密钥必须为 16 字节")
    x0, x1, x2, x3 = (_word(key, 0) ^ FK[0], _word(key, 4) ^ FK[1],
                      _word(key, 8) ^ FK[2], _word(key, 12) ^ FK[3])
    rk = []
    for i in range(32):
        nx = (x0 ^ _t_key((x1 ^ x2 ^ x3 ^ CK[i]) & _M)) & _M
        rk.append(nx)
        x0, x1, x2, x3 = x1, x2, x3, nx
    return rk


def _crypt_block(rk, block, off, out, ooff):
    x0, x1, x2, x3 = (_word(block, off), _word(block, off + 4),
                      _word(block, off + 8), _word(block, off + 12))
    for i in range(32):
        nx = (x0 ^ _t_enc((x1 ^ x2 ^ x3 ^ rk[i]) & _M)) & _M
        x0, x1, x2, x3 = x1, x2, x3, nx
    # 反序变换 R：输出 (X35, X34, X33, X32)
    _put_word(out, ooff, x3)
    _put_word(out, ooff + 4, x2)
    _put_word(out, ooff + 8, x1)
    _put_word(out, ooff + 12, x0)


def _pad(data):
    n = 16 - len(data) % 16
    return bytes(data) + bytes([n]) * n


def _unpad(data):
    if not data or len(data) % 16:
        raise ValueError("非法密文长度")
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充校验失败")
    return data[:-n]


def _ecb_raw(rk, data, decrypt):
    if len(data) % 16:
        raise ValueError("数据长度必须是 16 的倍数")
    rk_use = rk[::-1] if decrypt else rk
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        _crypt_block(rk_use, data, off, out, off)
    return bytes(out)


def _xor16(a, b, aoff=0):
    return bytes(a[aoff + i] ^ b[i] for i in range(16))


def ecb_encrypt(key, data):
    """SM4-ECB + PKCS7。key：16 字节；data：任意长度 bytes。"""
    return _ecb_raw(round_keys(key), _pad(data), False)


def ecb_decrypt(key, data):
    """SM4-ECB 解密并去除 PKCS7 填充。"""
    return _unpad(_ecb_raw(round_keys(key), data, True))


def cbc_encrypt(key, iv, data):
    """SM4-CBC + PKCS7。key/iv：16 字节。"""
    if len(iv) != 16:
        raise ValueError("IV 必须为 16 字节")
    rk = round_keys(key)
    padded = _pad(data)
    out = bytearray(len(padded))
    prev = iv
    for off in range(0, len(padded), 16):
        blk = _ecb_raw(rk, _xor16(padded, prev, off), False)
        out[off:off + 16] = blk
        prev = blk
    return bytes(out)


def cbc_decrypt(key, iv, data):
    """SM4-CBC 解密并去除 PKCS7 填充。"""
    if len(iv) != 16:
        raise ValueError("IV 必须为 16 字节")
    if not data or len(data) % 16:
        raise ValueError("非法密文长度")
    rk = round_keys(key)
    out = bytearray(len(data))
    prev = iv
    for off in range(0, len(data), 16):
        blk = _ecb_raw(rk, data[off:off + 16], True)
        out[off:off + 16] = _xor16(blk, prev)
        prev = data[off:off + 16]
    return _unpad(bytes(out))


# ==================== 标准测试向量 ====================
# 向量1：GB/T 32907-2016 附录A 示例1（首块密文；库会自动 PKCS7 填充，故取前 16 字节比对）
KAT1_KEY = "0123456789abcdeffedcba9876543210"
KAT1_PT = "0123456789abcdeffedcba9876543210"
KAT1_CT = "681edf34d206965e86b3e94f536e4246"
# 向量2：GB/T 32907-2016 附录A 示例2——同一密钥/明文连续加密 1,000,000 次（加 --long 运行）
KAT_LONG_CT = "595298c7c6fd271f0402f804c33d3f66"


def self_test(long_mode=False):
    ok = True
    key, pt = bytes.fromhex(KAT1_KEY), bytes.fromhex(KAT1_PT)
    got = ecb_encrypt(key, pt)[:16].hex()
    back = ecb_decrypt(key, ecb_encrypt(key, pt))
    good = got == KAT1_CT and back == pt
    ok &= good
    print(f"KAT1 ecb: {'PASS' if good else 'FAIL'} got={got}")
    # ECB / CBC 往返 + 边界（0/1/15/16/17/100 字节）
    import os
    for n in (0, 1, 15, 16, 17, 100):
        data = os.urandom(n)
        k, iv = os.urandom(16), os.urandom(16)
        ok &= ecb_decrypt(k, ecb_encrypt(k, data)) == data
        ok &= cbc_decrypt(k, iv, cbc_encrypt(k, iv, data)) == data
    # CBC 链式验证：密文首块 = E(P1 xor IV)
    k, iv = key, bytes.fromhex("fedcba98765432100123456789abcdef")
    ct = cbc_encrypt(k, iv, pt)
    ecb_ref = ecb_encrypt(k, _xor16(pt, iv))
    good = ct[:16] == ecb_ref[:16]
    ok &= good
    print(f"KAT  cbc-chain: {'PASS' if good else 'FAIL'}")
    if long_mode:
        rk = round_keys(key)
        x = pt
        for _ in range(1000000):
            x = _ecb_raw(rk, x, False)
        good = x.hex() == KAT_LONG_CT
        ok &= good
        print(f"KAT2 1M-iterations: {'PASS' if good else 'FAIL'} got={x.hex()}")
    print("ALL", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if self_test(long_mode="--long" in sys.argv) else 1)
