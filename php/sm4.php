<?php
/**
 * SM4Kit · PHP 实现
 * SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，零依赖。
 *
 * 自测: php sm4.php          快速向量
 *       php sm4.php --long   附加 100 万次迭代向量（较慢）
 */

const SM4_SBOX = [
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

/** τ：S 盒逐字节代换（PHP int 64 位，逐步掩码到 32 位） */
function sm4_tau(int $w): int {
    $r = 0;
    for ($i = 0; $i < 4; $i++) {
        $r = ($r << 8) | SM4_SBOX[($w >> (24 - 8 * $i)) & 255];
    }
    return $r & 0xFFFFFFFF;
}

function sm4_rotl(int $x, int $n): int {
    return (($x << $n) | ($x >> (32 - $n))) & 0xFFFFFFFF;
}

/** 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24 */
function sm4_tEnc(int $x): int {
    $b = sm4_tau($x);
    return ($b ^ sm4_rotl($b, 2) ^ sm4_rotl($b, 10) ^ sm4_rotl($b, 18) ^ sm4_rotl($b, 24)) & 0xFFFFFFFF;
}

/** 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23 */
function sm4_tKey(int $x): int {
    $b = sm4_tau($x);
    return ($b ^ sm4_rotl($b, 13) ^ sm4_rotl($b, 23)) & 0xFFFFFFFF;
}

function sm4_word(string $buf, int $off): int {
    return ((ord($buf[$off]) << 24) | (ord($buf[$off + 1]) << 16)
          | (ord($buf[$off + 2]) << 8) | ord($buf[$off + 3])) & 0xFFFFFFFF;
}

/** 计算 32 个轮密钥。key 必须 16 字节。 */
function sm4_round_keys(string $key): array {
    if (strlen($key) !== 16) {
        throw new InvalidArgumentException('SM4 密钥必须为 16 字节');
    }
    $fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
    $x = [];
    for ($i = 0; $i < 4; $i++) {
        $x[$i] = (sm4_word($key, 4 * $i) ^ $fk[$i]) & 0xFFFFFFFF;
    }
    $rk = [];
    for ($i = 0; $i < 32; $i++) {
        $ckByte = function (int $j) use ($i): int {
            return ((4 * $i + $j) * 7) % 256;
        };
        $ck = ($ckByte(0) << 24) | ($ckByte(1) << 16) | ($ckByte(2) << 8) | $ckByte(3);
        $nx = ($x[0] ^ sm4_tKey((($x[1] ^ $x[2] ^ $x[3] ^ $ck) & 0xFFFFFFFF))) & 0xFFFFFFFF;
        $rk[] = $nx;
        array_shift($x);
        $x[] = $nx;
    }
    return $rk;
}

function sm4_crypt_block(array $rk, string $src, int $off): string {
    $x = [sm4_word($src, $off), sm4_word($src, $off + 4), sm4_word($src, $off + 8), sm4_word($src, $off + 12)];
    for ($i = 0; $i < 32; $i++) {
        $nx = ($x[0] ^ sm4_tEnc((($x[1] ^ $x[2] ^ $x[3] ^ $rk[$i]) & 0xFFFFFFFF))) & 0xFFFFFFFF;
        array_shift($x);
        $x[] = $nx;
    }
    // 反序变换 R
    $out = '';
    foreach ([$x[3], $x[2], $x[1], $x[0]] as $w) {
        $out .= pack('N', $w);
    }
    return $out;
}

function sm4_pad(string $data): string {
    $n = 16 - (strlen($data) % 16);
    return $data . str_repeat(chr($n), $n);
}

function sm4_unpad(string $data): string {
    if ($data === '' || strlen($data) % 16 !== 0) {
        throw new RuntimeException('非法密文长度');
    }
    $n = ord($data[strlen($data) - 1]);
    if ($n < 1 || $n > 16 || substr($data, -$n) !== str_repeat(chr($n), $n)) {
        throw new RuntimeException('PKCS7 填充校验失败');
    }
    return substr($data, 0, strlen($data) - $n);
}

function sm4_ecb_raw(array $rk, string $data, bool $decrypt): string {
    if (strlen($data) % 16 !== 0) {
        throw new RuntimeException('数据长度必须是 16 的倍数');
    }
    if ($decrypt) {
        $rk = array_reverse($rk);
    }
    $out = '';
    for ($off = 0, $len = strlen($data); $off < $len; $off += 16) {
        $out .= sm4_crypt_block($rk, $data, $off);
    }
    return $out;
}

function sm4_xor16(string $a, string $b): string {
    return $a ^ $b; // PHP 字符串按字节异或
}

/** SM4-ECB + PKCS7。key：16 字节。 */
function sm4_ecb_encrypt(string $key, string $data): string {
    return sm4_ecb_raw(sm4_round_keys($key), sm4_pad($data), false);
}

/** SM4-ECB 解密并去除 PKCS7 填充。 */
function sm4_ecb_decrypt(string $key, string $data): string {
    return sm4_unpad(sm4_ecb_raw(sm4_round_keys($key), $data, true));
}

/** SM4-CBC + PKCS7。key/iv：16 字节。 */
function sm4_cbc_encrypt(string $key, string $iv, string $data): string {
    if (strlen($iv) !== 16) {
        throw new InvalidArgumentException('IV 必须为 16 字节');
    }
    $rk = sm4_round_keys($key);
    $padded = sm4_pad($data);
    $out = '';
    $prev = $iv;
    for ($off = 0, $len = strlen($padded); $off < $len; $off += 16) {
        $blk = sm4_ecb_raw($rk, sm4_xor16(substr($padded, $off, 16), $prev), false);
        $out .= $blk;
        $prev = $blk;
    }
    return $out;
}

/** SM4-CBC 解密并去除 PKCS7 填充。 */
function sm4_cbc_decrypt(string $key, string $iv, string $data): string {
    if (strlen($iv) !== 16) {
        throw new InvalidArgumentException('IV 必须为 16 字节');
    }
    if ($data === '' || strlen($data) % 16 !== 0) {
        throw new RuntimeException('非法密文长度');
    }
    $rk = sm4_round_keys($key);
    $out = '';
    $prev = $iv;
    for ($off = 0, $len = strlen($data); $off < $len; $off += 16) {
        $blk = sm4_ecb_raw($rk, substr($data, $off, 16), true);
        $out .= sm4_xor16($blk, $prev);
        $prev = substr($data, $off, 16);
    }
    return sm4_unpad($out);
}

// ==================== 标准测试向量 ====================
function sm4_self_test(bool $longMode = false): bool {
    $ok = true;
    $key = hex2bin('0123456789abcdeffedcba9876543210');
    $pt = hex2bin('0123456789abcdeffedcba9876543210');
    $got = bin2hex(substr(sm4_ecb_encrypt($key, $pt), 0, 16));
    $good = $got === '681edf34d206965e86b3e94f536e4246'
        && sm4_ecb_decrypt($key, sm4_ecb_encrypt($key, $pt)) === $pt;
    $ok = $ok && $good;
    printf("KAT1 ecb: %s got=%s\n", $good ? 'PASS' : 'FAIL', $got);
    // 往返 + 边界
    foreach ([0, 1, 15, 16, 17, 100] as $n) {
        $data = random_bytes($n);
        $k = random_bytes(16);
        $iv = random_bytes(16);
        $ok = $ok && sm4_ecb_decrypt($k, sm4_ecb_encrypt($k, $data)) === $data;
        $ok = $ok && sm4_cbc_decrypt($k, $iv, sm4_cbc_encrypt($k, $iv, $data)) === $data;
    }
    // CBC 链式验证
    $iv = hex2bin('fedcba98765432100123456789abcdef');
    $ct = sm4_cbc_encrypt($key, $iv, $pt);
    $ref = sm4_ecb_encrypt($key, sm4_xor16($pt, $iv));
    $good = substr($ct, 0, 16) === substr($ref, 0, 16);
    $ok = $ok && $good;
    printf("KAT  cbc-chain: %s\n", $good ? 'PASS' : 'FAIL');
    if ($longMode) {
        // 100 万次迭代向量（GB/T 32907 示例2）
        $rk = sm4_round_keys($key);
        $x = $pt;
        for ($i = 0; $i < 1000000; $i++) {
            $x = sm4_crypt_block($rk, $x, 0);
        }
        $good = bin2hex($x) === '595298c7c6fd271f0402f804c33d3f66';
        $ok = $ok && $good;
        printf("KAT2 1M-iterations: %s got=%s\n", $good ? 'PASS' : 'FAIL', bin2hex($x));
    }
    printf("ALL %s\n", $ok ? 'PASS' : 'FAIL');
    return $ok;
}

if (PHP_SAPI === 'cli' && realpath($argv[0]) === __FILE__) {
    exit(sm4_self_test(in_array('--long', $argv, true)) ? 0 : 1);
}
