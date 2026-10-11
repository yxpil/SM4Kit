//! SM4Kit · Rust 实现
//! SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，零依赖（std 亦非必需，仅 Vec 使用）。
//!
//! ```no_run
//! use sm4kit::{cbc_encrypt, cbc_decrypt};
//! let key = [0x01u8; 16];
//! let iv = [0x02u8; 16];
//! let ct = cbc_encrypt(&key, &iv, b"hello");
//! let pt = cbc_decrypt(&key, &iv, &ct).unwrap();
//! ```

const SBOX: [u8; 256] = [
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
];
const FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

// ck[i] = 4 字节，每字节 ((4i+j)*7) mod 256
fn ck(i: usize) -> u32 {
    let b = |j: usize| (((4 * i + j) * 7) % 256) as u32;
    b(0) << 24 | b(1) << 16 | b(2) << 8 | b(3)
}

fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// τ：S 盒逐字节代换
fn tau(w: u32) -> u32 {
    u32::from(SBOX[(w >> 24) as usize]) << 24
        | u32::from(SBOX[((w >> 16) & 255) as usize]) << 16
        | u32::from(SBOX[((w >> 8) & 255) as usize]) << 8
        | u32::from(SBOX[(w & 255) as usize])
}

/// 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24
fn t_enc(x: u32) -> u32 {
    let b = tau(x);
    b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

/// 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23
fn t_key(x: u32) -> u32 {
    let b = tau(x);
    b ^ rotl(b, 13) ^ rotl(b, 23)
}

fn word(buf: &[u8], off: usize) -> u32 {
    u32::from(buf[off]) << 24 | u32::from(buf[off + 1]) << 16 | u32::from(buf[off + 2]) << 8
        | u32::from(buf[off + 3])
}

fn put_word(out: &mut [u8], off: usize, w: u32) {
    out[off] = (w >> 24) as u8;
    out[off + 1] = (w >> 16) as u8;
    out[off + 2] = (w >> 8) as u8;
    out[off + 3] = w as u8;
}

/// 计算 32 个轮密钥。key 必须 16 字节。
pub fn round_keys(key: &[u8]) -> Vec<u32> {
    assert_eq!(key.len(), 16, "SM4 密钥必须为 16 字节");
    let (mut x0, mut x1, mut x2, mut x3) =
        (word(key, 0) ^ FK[0], word(key, 4) ^ FK[1], word(key, 8) ^ FK[2], word(key, 12) ^ FK[3]);
    let mut rk = Vec::with_capacity(32);
    for i in 0..32 {
        let nx = x0 ^ t_key(x1 ^ x2 ^ x3 ^ ck(i));
        rk.push(nx);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = nx;
    }
    rk
}

fn crypt_block(rk: &[u32], src: &[u8], off: usize, out: &mut [u8], ooff: usize) {
    let (mut x0, mut x1, mut x2, mut x3) =
        (word(src, off), word(src, off + 4), word(src, off + 8), word(src, off + 12));
    for i in 0..32 {
        let nx = x0 ^ t_enc(x1 ^ x2 ^ x3 ^ rk[i]);
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = nx;
    }
    // 反序变换 R
    put_word(out, ooff, x3);
    put_word(out, ooff + 4, x2);
    put_word(out, ooff + 8, x1);
    put_word(out, ooff + 12, x0);
}

fn pad(data: &[u8]) -> Vec<u8> {
    let n = 16 - data.len() % 16;
    let mut out = data.to_vec();
    out.resize(data.len() + n, n as u8);
    out
}

fn unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err("非法密文长度".into());
    }
    let n = data[data.len() - 1] as usize;
    if !(1..=16).contains(&n) || data[data.len() - n..].iter().any(|&b| b as usize != n) {
        return Err("PKCS7 填充校验失败".into());
    }
    Ok(data[..data.len() - n].to_vec())
}

fn ecb_raw(rk: &[u32], data: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    if data.len() % 16 != 0 {
        return Err("数据长度必须是 16 的倍数".into());
    }
    let use_rk: Vec<u32> = if decrypt { rk.iter().rev().copied().collect() } else { rk.to_vec() };
    let mut out = vec![0u8; data.len()];
    for off in (0..data.len()).step_by(16) {
        crypt_block(&use_rk, data, off, &mut out, off);
    }
    Ok(out)
}

fn xor16(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// SM4-ECB + PKCS7。key：16 字节。
pub fn ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    ecb_raw(&round_keys(key), &pad(data), false).unwrap()
}

/// SM4-ECB 解密并去除 PKCS7 填充。
pub fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    unpad(&ecb_raw(&round_keys(key), data, true)?)
}

/// SM4-CBC + PKCS7。key/iv：16 字节。
pub fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), 16, "IV 必须为 16 字节");
    let rk = round_keys(key);
    let padded = pad(data);
    let mut out = vec![0u8; padded.len()];
    let mut prev: [u8; 16] = iv.try_into().unwrap();
    for off in (0..padded.len()).step_by(16) {
        let blk = ecb_raw(&rk, &xor16(&padded[off..off + 16], &prev), false).unwrap();
        out[off..off + 16].copy_from_slice(&blk);
        prev = blk.try_into().unwrap();
    }
    out
}

/// SM4-CBC 解密并去除 PKCS7 填充。
pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    assert_eq!(iv.len(), 16, "IV 必须为 16 字节");
    if data.is_empty() || data.len() % 16 != 0 {
        return Err("非法密文长度".into());
    }
    let rk = round_keys(key);
    let mut out = vec![0u8; data.len()];
    let mut prev: [u8; 16] = iv.try_into().unwrap();
    for off in (0..data.len()).step_by(16) {
        let blk = ecb_raw(&rk, &data[off..off + 16], true)?;
        out[off..off + 16].copy_from_slice(&xor16(&blk, &prev));
        prev.copy_from_slice(&data[off..off + 16]);
    }
    unpad(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KAT1_KEY: &str = "0123456789abcdeffedcba9876543210";
    const KAT1_PT: &str = "0123456789abcdeffedcba9876543210";
    const KAT1_CT: &str = "681edf34d206965e86b3e94f536e4246";
    const KAT_LONG_CT: &str = "595298c7c6fd271f0402f804c33d3f66";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn kat1_gb32907() {
        let key = unhex(KAT1_KEY);
        let pt = unhex(KAT1_PT);
        assert_eq!(&hex(&ecb_encrypt(&key, &pt)[..16]), KAT1_CT);
        assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &pt)).unwrap(), pt);
    }

    #[test]
    fn roundtrip_edges() {
        for n in [0usize, 1, 15, 16, 17, 100] {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 % 251) as u8).collect();
            let key = unhex(KAT1_KEY);
            let iv = unhex("fedcba98765432100123456789abcdef");
            assert_eq!(ecb_decrypt(&key, &ecb_encrypt(&key, &data)).unwrap(), data);
            assert_eq!(cbc_decrypt(&key, &iv, &cbc_encrypt(&key, &iv, &data)).unwrap(), data);
        }
    }

    #[test]
    fn cbc_chain() {
        let key = unhex(KAT1_KEY);
        let pt = unhex(KAT1_PT);
        let iv = unhex("fedcba98765432100123456789abcdef");
        let ct = cbc_encrypt(&key, &iv, &pt);
        let r = ecb_encrypt(&key, &xor16(&pt, &iv));
        assert_eq!(ct[..16], r[..16]);
    }

    #[test]
    fn kat2_million_iterations() {
        let key = unhex(KAT1_KEY);
        let rk = round_keys(&key);
        let mut x = unhex(KAT1_PT);
        for _ in 0..1_000_000 {
            let tmp = x.clone();
            crypt_block(&rk, &tmp, 0, &mut x, 0);
        }
        assert_eq!(hex(&x), KAT_LONG_CT);
    }
}
