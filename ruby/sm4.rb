# frozen_string_literal: true

# SM4Kit · Ruby 实现
# SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，零依赖。
#
# 自测: ruby sm4.rb          快速向量
#       ruby sm4.rb --long   附加 100 万次迭代向量（较慢）
module SM4Kit
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
  ].freeze

  MASK = 0xFFFFFFFF

  module_function

  def rotl(x, n)
    ((x << n) | (x >> (32 - n))) & MASK
  end

  # τ：S 盒逐字节代换
  def tau(w)
    (SBOX[(w >> 24) & 255] << 24 | SBOX[(w >> 16) & 255] << 16 |
     SBOX[(w >> 8) & 255] << 8 | SBOX[w & 255]) & MASK
  end

  # 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24
  def t_enc(x)
    b = tau(x)
    (b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)) & MASK
  end

  # 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23
  def t_key(x)
    b = tau(x)
    (b ^ rotl(b, 13) ^ rotl(b, 23)) & MASK
  end

  def word(buf, off)
    (buf[off].ord << 24 | buf[off + 1].ord << 16 | buf[off + 2].ord << 8 | buf[off + 3].ord) & MASK
  end

  # 计算 32 个轮密钥。key 必须 16 字节。
  def round_keys(key)
    raise ArgumentError, 'SM4 密钥必须为 16 字节' unless key.bytesize == 16

    fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    b = ->(j, i) { ((4 * i + j) * 7) % 256 }
    x = [word(key, 0) ^ fk[0], word(key, 4) ^ fk[1], word(key, 8) ^ fk[2], word(key, 12) ^ fk[3]]
    rk = []
    32.times do |i|
      ck = b.(0, i) << 24 | b.(1, i) << 16 | b.(2, i) << 8 | b.(3, i)
      nx = (x[0] ^ t_key((x[1] ^ x[2] ^ x[3] ^ ck) & MASK)) & MASK
      rk << nx
      x = [x[1], x[2], x[3], nx]
    end
    rk
  end

  def crypt_block(rk, block)
    x = [word(block, 0), word(block, 4), word(block, 8), word(block, 12)]
    32.times do |i|
      nx = (x[0] ^ t_enc((x[1] ^ x[2] ^ x[3] ^ rk[i]) & MASK)) & MASK
      x = [x[1], x[2], x[3], nx]
    end
    # 反序变换 R
    [x[3], x[2], x[1], x[0]].pack('N4')
  end

  def pad(data)
    n = 16 - data.bytesize % 16
    data + ([n].pack('C') * n)
  end

  def unpad(data)
    raise ArgumentError, '非法密文长度' if data.empty? || data.bytesize % 16 != 0

    n = data.getbyte(data.bytesize - 1)
    raise ArgumentError, 'PKCS7 填充校验失败' if n < 1 || n > 16 || data[-n..] != ([n].pack('C') * n)

    data[0...-n]
  end

  def ecb_raw(rk, data, decrypt)
    raise ArgumentError, '数据长度必须是 16 的倍数' if data.bytesize % 16 != 0

    use = decrypt ? rk.reverse : rk
    out = +''
    (0...data.bytesize).step(16) { |off| out << crypt_block(use, data[off, 16]) }
    out
  end

  def xor16(a, b)
    a.bytes.zip(b.bytes).map { |x, y| (x ^ y) }.pack('C*')
  end

  # SM4-ECB + PKCS7。key：16 字节。
  def ecb_encrypt(key, data)
    ecb_raw(round_keys(key), pad(data), false)
  end

  # SM4-ECB 解密并去除 PKCS7 填充。
  def ecb_decrypt(key, data)
    unpad(ecb_raw(round_keys(key), data, true))
  end

  # SM4-CBC + PKCS7。key/iv：16 字节。
  def cbc_encrypt(key, iv, data)
    raise ArgumentError, 'IV 必须为 16 字节' unless iv.bytesize == 16

    rk = round_keys(key)
    padded = pad(data)
    out = +''
    prev = iv
    (0...padded.bytesize).step(16) do |off|
      blk = ecb_raw(rk, xor16(padded[off, 16], prev), false)
      out << blk
      prev = blk
    end
    out
  end

  # SM4-CBC 解密并去除 PKCS7 填充。
  def cbc_decrypt(key, iv, data)
    raise ArgumentError, 'IV 必须为 16 字节' unless iv.bytesize == 16
    raise ArgumentError, '非法密文长度' if data.empty? || data.bytesize % 16 != 0

    rk = round_keys(key)
    out = +''
    prev = iv
    (0...data.bytesize).step(16) do |off|
      blk = ecb_raw(rk, data[off, 16], true)
      out << xor16(blk, prev)
      prev = data[off, 16]
    end
    unpad(out)
  end

  # ==================== 标准测试向量 ====================
  KAT1_KEY = '0123456789abcdeffedcba9876543210'
  KAT1_PT  = '0123456789abcdeffedcba9876543210'
  KAT1_CT  = '681edf34d206965e86b3e94f536e4246'
  KAT_LONG_CT = '595298c7c6fd271f0402f804c33d3f66'

  def self_test(long_mode: false)
    ok = true
    key = [KAT1_KEY].pack('H*')
    pt = [KAT1_PT].pack('H*')
    got = ecb_encrypt(key, pt)[0, 16].unpack1('H*')
    good = got == KAT1_CT && ecb_decrypt(key, ecb_encrypt(key, pt)) == pt
    ok &= good
    puts format('KAT1 ecb: %s got=%s', good ? 'PASS' : 'FAIL', got)
    # 往返 + 边界
    [0, 1, 15, 16, 17, 100].each do |n|
      data = Random.bytes(n)
      k = Random.bytes(16)
      iv = Random.bytes(16)
      ok &= ecb_decrypt(k, ecb_encrypt(k, data)) == data
      ok &= cbc_decrypt(k, iv, cbc_encrypt(k, iv, data)) == data
    end
    # CBC 链式验证
    iv = ['fedcba98765432100123456789abcdef'].pack('H*')
    ct = cbc_encrypt(key, iv, pt)
    ref = ecb_encrypt(key, xor16(pt, iv))
    good = ct[0, 16] == ref[0, 16]
    ok &= good
    puts format('KAT  cbc-chain: %s', good ? 'PASS' : 'FAIL')
    if long_mode
      # 100 万次迭代向量（GB/T 32907 示例2）
      rk = round_keys(key)
      x = pt
      1_000_000.times { x = crypt_block(rk, x) }
      good = x.unpack1('H*') == KAT_LONG_CT
      ok &= good
      puts format('KAT2 1M-iterations: %s got=%s', good ? 'PASS' : 'FAIL', x.unpack1('H*'))
    end
    puts "ALL #{ok ? 'PASS' : 'FAIL'}"
    ok
  end
end

SM4Kit.self_test(long_mode: ARGV.include?('--long')) || exit(1) if $PROGRAM_NAME == __FILE__
