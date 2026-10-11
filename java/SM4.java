/*
 * SM4Kit · Java 实现
 * SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，纯 JDK、零依赖。
 *
 * 编译运行自测: javac SM4.java && java SM4
 */
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public final class SM4 {

    private static final int[] SBOX = {
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
    private static final int FK0 = 0xa3b1bac6, FK1 = 0x56aa3350, FK2 = 0x677d9197, FK3 = 0xb27022dc;
    // ck[i] = 4 字节，每字节 ((4i+j)*7) mod 256
    private static final int[] CK = new int[32];
    static {
        for (int i = 0; i < 32; i++) {
            CK[i] = (((4 * i + 0) * 7) % 256) << 24 | (((4 * i + 1) * 7) % 256) << 16
                  | (((4 * i + 2) * 7) % 256) << 8 | (((4 * i + 3) * 7) % 256);
        }
    }

    private SM4() {}

    private static int rotl(int x, int n) { return (x << n) | (x >>> (32 - n)); }

    /** τ：S 盒逐字节代换 */
    private static int tau(int w) {
        return (SBOX[(w >>> 24) & 255] << 24) | (SBOX[(w >>> 16) & 255] << 16)
             | (SBOX[(w >>> 8) & 255] << 8) | SBOX[w & 255];
    }

    /** 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24 */
    private static int tEnc(int x) {
        int b = tau(x);
        return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
    }

    /** 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23 */
    private static int tKey(int x) {
        int b = tau(x);
        return b ^ rotl(b, 13) ^ rotl(b, 23);
    }

    private static int word(byte[] b, int off) {
        return (b[off] & 255) << 24 | (b[off + 1] & 255) << 16 | (b[off + 2] & 255) << 8 | (b[off + 3] & 255);
    }

    private static void putWord(byte[] out, int off, int w) {
        out[off] = (byte) (w >>> 24);
        out[off + 1] = (byte) (w >>> 16);
        out[off + 2] = (byte) (w >>> 8);
        out[off + 3] = (byte) w;
    }

    /** 计算 32 个轮密钥。key 必须 16 字节。 */
    public static int[] roundKeys(byte[] key) {
        if (key == null || key.length != 16) throw new IllegalArgumentException("SM4 密钥必须为 16 字节");
        int x0 = word(key, 0) ^ FK0, x1 = word(key, 4) ^ FK1;
        int x2 = word(key, 8) ^ FK2, x3 = word(key, 12) ^ FK3;
        int[] rk = new int[32];
        for (int i = 0; i < 32; i++) {
            int nx = x0 ^ tKey(x1 ^ x2 ^ x3 ^ CK[i]);
            rk[i] = nx;
            x0 = x1; x1 = x2; x2 = x3; x3 = nx;
        }
        return rk;
    }

    private static void cryptBlock(int[] rk, byte[] src, int off, byte[] out, int ooff) {
        int x0 = word(src, off), x1 = word(src, off + 4), x2 = word(src, off + 8), x3 = word(src, off + 12);
        for (int i = 0; i < 32; i++) {
            int nx = x0 ^ tEnc(x1 ^ x2 ^ x3 ^ rk[i]);
            x0 = x1; x1 = x2; x2 = x3; x3 = nx;
        }
        // 反序变换 R
        putWord(out, ooff, x3);
        putWord(out, ooff + 4, x2);
        putWord(out, ooff + 8, x1);
        putWord(out, ooff + 12, x0);
    }

    private static byte[] pad(byte[] data) {
        int n = 16 - data.length % 16;
        byte[] out = Arrays.copyOf(data, data.length + n);
        Arrays.fill(out, data.length, out.length, (byte) n);
        return out;
    }

    private static byte[] unpad(byte[] data) {
        if (data.length == 0 || data.length % 16 != 0) throw new IllegalArgumentException("非法密文长度");
        int n = data[data.length - 1] & 255;
        if (n < 1 || n > 16) throw new IllegalArgumentException("PKCS7 填充校验失败");
        for (int i = data.length - n; i < data.length; i++)
            if ((data[i] & 255) != n) throw new IllegalArgumentException("PKCS7 填充校验失败");
        return Arrays.copyOf(data, data.length - n);
    }

    private static byte[] ecbRaw(int[] rk, byte[] data, boolean decrypt) {
        if (data.length % 16 != 0) throw new IllegalArgumentException("数据长度必须是 16 的倍数");
        int[] use = rk;
        if (decrypt) {
            use = new int[32];
            for (int i = 0; i < 32; i++) use[i] = rk[31 - i];
        }
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += 16) cryptBlock(use, data, off, out, off);
        return out;
    }

    private static byte[] xor16(byte[] a, byte[] b) {
        byte[] o = new byte[16];
        for (int i = 0; i < 16; i++) o[i] = (byte) (a[i] ^ b[i]);
        return o;
    }

    /** SM4-ECB + PKCS7。key：16 字节。 */
    public static byte[] ecbEncrypt(byte[] key, byte[] data) { return ecbRaw(roundKeys(key), pad(data), false); }

    /** SM4-ECB 解密并去除 PKCS7 填充。 */
    public static byte[] ecbDecrypt(byte[] key, byte[] data) { return unpad(ecbRaw(roundKeys(key), data, true)); }

    /** SM4-CBC + PKCS7。key/iv：16 字节。 */
    public static byte[] cbcEncrypt(byte[] key, byte[] iv, byte[] data) {
        if (iv == null || iv.length != 16) throw new IllegalArgumentException("IV 必须为 16 字节");
        int[] rk = roundKeys(key);
        byte[] padded = pad(data);
        byte[] out = new byte[padded.length];
        byte[] prev = iv.clone();
        for (int off = 0; off < padded.length; off += 16) {
            byte[] blk = ecbRaw(rk, xor16(Arrays.copyOfRange(padded, off, off + 16), prev), false);
            System.arraycopy(blk, 0, out, off, 16);
            prev = Arrays.copyOfRange(out, off, off + 16);
        }
        return out;
    }

    /** SM4-CBC 解密并去除 PKCS7 填充。 */
    public static byte[] cbcDecrypt(byte[] key, byte[] iv, byte[] data) {
        if (iv == null || iv.length != 16) throw new IllegalArgumentException("IV 必须为 16 字节");
        if (data.length == 0 || data.length % 16 != 0) throw new IllegalArgumentException("非法密文长度");
        int[] rk = roundKeys(key);
        byte[] out = new byte[data.length];
        byte[] prev = iv.clone();
        for (int off = 0; off < data.length; off += 16) {
            byte[] blk = ecbRaw(rk, Arrays.copyOfRange(data, off, off + 16), true);
            System.arraycopy(xor16(blk, prev), 0, out, off, 16);
            prev = Arrays.copyOfRange(data, off, off + 16);
        }
        return unpad(out);
    }

    // ==================== 标准测试向量 ====================
    private static final String KAT1_KEY = "0123456789abcdeffedcba9876543210";
    private static final String KAT1_PT = "0123456789abcdeffedcba9876543210";
    private static final String KAT1_CT = "681edf34d206965e86b3e94f536e4246";
    private static final String KAT_LONG_CT = "595298c7c6fd271f0402f804c33d3f66";

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** 自测（含 100 万次迭代标准向量）。 */
    public static boolean selfTest() {
        boolean ok = true;
        byte[] key = unhex(KAT1_KEY), pt = unhex(KAT1_PT);
        String got = hex(Arrays.copyOf(ecbEncrypt(key, pt), 16));
        boolean good = got.equals(KAT1_CT) && Arrays.equals(ecbDecrypt(key, ecbEncrypt(key, pt)), pt);
        ok &= good;
        System.out.printf("KAT1 ecb: %s got=%s%n", good ? "PASS" : "FAIL", got);
        SecureRandom rnd = new SecureRandom();
        for (int n : new int[]{0, 1, 15, 16, 17, 100}) {
            byte[] data = new byte[n];
            rnd.nextBytes(data);
            byte[] k = new byte[16], iv = new byte[16];
            rnd.nextBytes(k);
            rnd.nextBytes(iv);
            ok &= Arrays.equals(ecbDecrypt(k, ecbEncrypt(k, data)), data);
            ok &= Arrays.equals(cbcDecrypt(k, iv, cbcEncrypt(k, iv, data)), data);
        }
        byte[] iv = unhex("fedcba98765432100123456789abcdef");
        byte[] ct = cbcEncrypt(key, iv, pt);
        byte[] ref = ecbEncrypt(key, xor16(pt, iv));
        good = hex(Arrays.copyOf(ct, 16)).equals(hex(Arrays.copyOf(ref, 16)));
        ok &= good;
        System.out.printf("KAT  cbc-chain: %s%n", good ? "PASS" : "FAIL");
        // 100 万次迭代向量（GB/T 32907 示例2）
        int[] rk = roundKeys(key);
        byte[] x = pt.clone();
        for (int i = 0; i < 1_000_000; i++) cryptBlock(rk, x, 0, x, 0);
        good = hex(x).equals(KAT_LONG_CT);
        ok &= good;
        System.out.printf("KAT2 1M-iterations: %s got=%s%n", good ? "PASS" : "FAIL", hex(x));
        System.out.println("ALL " + (ok ? "PASS" : "FAIL"));
        return ok;
    }

    public static void main(String[] args) {
        System.exit(selfTest() ? 0 : 1);
    }
}
