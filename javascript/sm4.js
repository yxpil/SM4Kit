/**
 * SM4Kit · JavaScript 实现
 * SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，零依赖，Node 与浏览器通用。
 *
 * Node:
 *   const { ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt } = require('./sm4.js');
 *   const ct = cbcEncrypt(key16, iv16, Buffer.from('hello'));
 *   const pt = cbcDecrypt(key16, iv16, ct);
 * 浏览器:
 *   <script src="sm4.js"></script>  →  window.sm4kit.ecbEncrypt(...)
 *
 * 自测: node sm4.js          快速向量
 *       node sm4.js --long   附加 100 万次迭代向量（较慢）
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.sm4kit = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const SBOX = [
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
  const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
  // CK[i] = 4 字节，每字节 ((4i+j)*7) mod 256
  const CK = Array.from({ length: 32 }, (_, i) => {
    const b = j => ((4 * i + j) * 7) % 256;
    return ((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)) >>> 0;
  });

  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

  /** τ：S 盒逐字节代换 */
  function tau(w) {
    return ((SBOX[(w >>> 24) & 255] << 24) | (SBOX[(w >>> 16) & 255] << 16) |
      (SBOX[(w >>> 8) & 255] << 8) | SBOX[w & 255]) >>> 0;
  }
  /** 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24 */
  function tEnc(x) {
    const b = tau(x);
    return (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) >>> 0;
  }
  /** 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23 */
  function tKey(x) {
    const b = tau(x);
    return (b ^ rotl(b, 13) ^ rotl(b, 23)) >>> 0;
  }
  const word = (buf, off) =>
    (((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0);
  const putWord = (out, off, w) => {
    out[off] = (w >>> 24) & 255; out[off + 1] = (w >>> 16) & 255;
    out[off + 2] = (w >>> 8) & 255; out[off + 3] = w & 255;
  };

  function roundKeys(key) {
    if (!key || key.length !== 16) throw new Error('SM4 密钥必须为 16 字节');
    let x0 = word(key, 0) ^ FK[0], x1 = word(key, 4) ^ FK[1];
    let x2 = word(key, 8) ^ FK[2], x3 = word(key, 12) ^ FK[3];
    const rk = [];
    for (let i = 0; i < 32; i++) {
      const nx = (x0 ^ tKey((x1 ^ x2 ^ x3 ^ CK[i]) >>> 0)) >>> 0;
      rk.push(nx);
      x0 = x1; x1 = x2; x2 = x3; x3 = nx;
    }
    return rk;
  }

  function cryptBlock(rk, src, off, out, ooff) {
    let x0 = word(src, off), x1 = word(src, off + 4), x2 = word(src, off + 8), x3 = word(src, off + 12);
    for (let i = 0; i < 32; i++) {
      const nx = (x0 ^ tEnc((x1 ^ x2 ^ x3 ^ rk[i]) >>> 0)) >>> 0;
      x0 = x1; x1 = x2; x2 = x3; x3 = nx;
    }
    // 反序变换 R
    putWord(out, ooff, x3); putWord(out, ooff + 4, x2);
    putWord(out, ooff + 8, x1); putWord(out, ooff + 12, x0);
  }

  function pad(data) {
    const n = 16 - (data.length % 16);
    const out = new Uint8Array(data.length + n);
    out.set(data, 0);
    for (let i = data.length; i < out.length; i++) out[i] = n;
    return out;
  }
  function unpad(data) {
    if (!data.length || data.length % 16) throw new Error('非法密文长度');
    const n = data[data.length - 1];
    if (n < 1 || n > 16) throw new Error('PKCS7 填充校验失败');
    for (let i = data.length - n; i < data.length; i++) if (data[i] !== n) throw new Error('PKCS7 填充校验失败');
    return data.slice(0, data.length - n);
  }

  function ecbRaw(rk, data, decrypt) {
    if (data.length % 16) throw new Error('数据长度必须是 16 的倍数');
    const use = decrypt ? rk.slice().reverse() : rk;
    const out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += 16) cryptBlock(use, data, off, out, off);
    return out;
  }
  const xor16 = (a, b, aoff = 0) => {
    const o = new Uint8Array(16);
    for (let i = 0; i < 16; i++) o[i] = a[aoff + i] ^ b[i];
    return o;
  };

  /** SM4-ECB + PKCS7。key：16 字节；data：Uint8Array / Buffer / 字节数组 */
  function ecbEncrypt(key, data) { return ecbRaw(roundKeys(key), pad(data), false); }
  /** SM4-ECB 解密并去除 PKCS7 填充 */
  function ecbDecrypt(key, data) { return unpad(ecbRaw(roundKeys(key), data, true)); }
  /** SM4-CBC + PKCS7。key/iv：16 字节 */
  function cbcEncrypt(key, iv, data) {
    if (!iv || iv.length !== 16) throw new Error('IV 必须为 16 字节');
    const rk = roundKeys(key), padded = pad(data);
    const out = new Uint8Array(padded.length);
    let prev = iv;
    for (let off = 0; off < padded.length; off += 16) {
      const blk = ecbRaw(rk, xor16(padded, prev, off), false);
      out.set(blk, off);
      prev = blk;
    }
    return out;
  }
  /** SM4-CBC 解密并去除 PKCS7 填充 */
  function cbcDecrypt(key, iv, data) {
    if (!iv || iv.length !== 16) throw new Error('IV 必须为 16 字节');
    if (!data.length || data.length % 16) throw new Error('非法密文长度');
    const rk = roundKeys(key);
    const out = new Uint8Array(data.length);
    let prev = iv;
    for (let off = 0; off < data.length; off += 16) {
      const blk = ecbRaw(rk, data.slice(off, off + 16), true);
      out.set(xor16(blk, prev), off);
      prev = data.slice(off, off + 16);
    }
    return unpad(out);
  }

  // ==================== 标准测试向量 ====================
  const KAT1_KEY = '0123456789abcdeffedcba9876543210';
  const KAT1_PT = '0123456789abcdeffedcba9876543210';
  const KAT1_CT = '681edf34d206965e86b3e94f536e4246';
  const KAT_LONG_CT = '595298c7c6fd271f0402f804c33d3f66';
  const hex2buf = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));
  const buf2hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

  function selfTest(longMode) {
    let ok = true;
    const key = hex2buf(KAT1_KEY), pt = hex2buf(KAT1_PT);
    const got = buf2hex(ecbEncrypt(key, pt).slice(0, 16));
    const back = ecbDecrypt(key, ecbEncrypt(key, pt));
    let good = got === KAT1_CT && buf2hex(back) === KAT1_PT;
    ok &= good;
    console.log(`KAT1 ecb: ${good ? 'PASS' : 'FAIL'} got=${got}`);
    // 往返 + 边界
    const rnd = n => { const a = new Uint8Array(n); for (let i = 0; i < n; i++) a[i] = (Math.random() * 256) | 0; return a; };
    for (const n of [0, 1, 15, 16, 17, 100]) {
      const data = rnd(n), k = rnd(16), iv = rnd(16);
      ok &= buf2hex(ecbDecrypt(k, ecbEncrypt(k, data))) === buf2hex(data);
      ok &= buf2hex(cbcDecrypt(k, iv, cbcEncrypt(k, iv, data))) === buf2hex(data);
    }
    // CBC 链式验证
    const iv = hex2buf('fedcba98765432100123456789abcdef');
    const ct = cbcEncrypt(key, iv, pt);
    const ref = ecbEncrypt(key, xor16(pt, iv));
    good = buf2hex(ct.slice(0, 16)) === buf2hex(ref.slice(0, 16));
    ok &= good;
    console.log(`KAT  cbc-chain: ${good ? 'PASS' : 'FAIL'}`);
    if (longMode) {
      const rk = roundKeys(key);
      let x = pt;
      for (let i = 0; i < 1000000; i++) x = ecbRaw(rk, x, false);
      good = buf2hex(x) === KAT_LONG_CT;
      ok &= good;
      console.log(`KAT2 1M-iterations: ${good ? 'PASS' : 'FAIL'} got=${buf2hex(x)}`);
    }
    console.log('ALL', ok ? 'PASS' : 'FAIL');
    return !!ok;
  }

  return { SBOX, roundKeys, ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt, selfTest };
});

if (typeof require !== 'undefined' && require.main === module) {
  process.exit(module.exports.selfTest(process.argv.includes('--long')) ? 0 : 1);
}
