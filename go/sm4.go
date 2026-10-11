// SM4Kit · Go 实现
// SM4 分组密码（GB/T 32907-2016）：ECB / CBC + PKCS7，纯标准库、零依赖。
//
// 运行自测: go run .
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

var sbox = [256]byte{
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
}

var fk = [4]uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

// ck[i] = 4 字节，每字节 ((4i+j)*7) mod 256
var ck = func() (c [32]uint32) {
	for i := 0; i < 32; i++ {
		c[i] = uint32(((4*i+0)*7)%256)<<24 | uint32(((4*i+1)*7)%256)<<16 |
			uint32(((4*i+2)*7)%256)<<8 | uint32(((4*i+3)*7)%256)
	}
	return
}()

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

// τ：S 盒逐字节代换
func tau(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 | uint32(sbox[(w>>16)&255])<<16 |
		uint32(sbox[(w>>8)&255])<<8 | uint32(sbox[w&255])
}

// 加密轮函数 T：τ + L(B)=B^rotl2^rotl10^rotl18^rotl24
func tEnc(x uint32) uint32 {
	b := tau(x)
	return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

// 密钥扩展轮函数 T'：τ + L'(B)=B^rotl13^rotl23
func tKey(x uint32) uint32 {
	b := tau(x)
	return b ^ rotl(b, 13) ^ rotl(b, 23)
}

func word(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

func putWord(out []byte, off int, w uint32) {
	out[off] = byte(w >> 24)
	out[off+1] = byte(w >> 16)
	out[off+2] = byte(w >> 8)
	out[off+3] = byte(w)
}

// RoundKeys 计算 32 个轮密钥。key 必须 16 字节。
func RoundKeys(key []byte) []uint32 {
	if len(key) != 16 {
		panic("sm4: 密钥必须为 16 字节")
	}
	x0, x1, x2, x3 := word(key, 0)^fk[0], word(key, 4)^fk[1], word(key, 8)^fk[2], word(key, 12)^fk[3]
	rk := make([]uint32, 32)
	for i := 0; i < 32; i++ {
		nx := x0 ^ tKey(x1^x2^x3^ck[i])
		rk[i] = nx
		x0, x1, x2, x3 = x1, x2, x3, nx
	}
	return rk
}

func cryptBlock(rk []uint32, src []byte, off int, out []byte, ooff int) {
	x0, x1, x2, x3 := word(src, off), word(src, off+4), word(src, off+8), word(src, off+12)
	for i := 0; i < 32; i++ {
		nx := x0 ^ tEnc(x1^x2^x3^rk[i])
		x0, x1, x2, x3 = x1, x2, x3, nx
	}
	// 反序变换 R
	putWord(out, ooff, x3)
	putWord(out, ooff+4, x2)
	putWord(out, ooff+8, x1)
	putWord(out, ooff+12, x0)
}

func pad(data []byte) []byte {
	n := 16 - len(data)%16
	return append(append([]byte{}, data...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errors.New("sm4: 非法密文长度")
	}
	n := int(data[len(data)-1])
	if n < 1 || n > 16 {
		return nil, errors.New("sm4: PKCS7 填充校验失败")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("sm4: PKCS7 填充校验失败")
		}
	}
	return data[:len(data)-n], nil
}

func ecbRaw(rk []uint32, data []byte, decrypt bool) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("sm4: 数据长度必须是 16 的倍数")
	}
	use := rk
	if decrypt {
		use = make([]uint32, 32)
		for i := 0; i < 32; i++ {
			use[i] = rk[31-i]
		}
	}
	out := make([]byte, len(data))
	for off := 0; off < len(data); off += 16 {
		cryptBlock(use, data, off, out, off)
	}
	return out, nil
}

func xor16(a, b []byte) []byte {
	o := make([]byte, 16)
	for i := 0; i < 16; i++ {
		o[i] = a[i] ^ b[i]
	}
	return o
}

// EcbEncrypt SM4-ECB + PKCS7。key：16 字节。
func EcbEncrypt(key, data []byte) []byte {
	out, _ := ecbRaw(RoundKeys(key), pad(data), false)
	return out
}

// EcbDecrypt SM4-ECB 解密并去除 PKCS7 填充。
func EcbDecrypt(key, data []byte) ([]byte, error) {
	raw, err := ecbRaw(RoundKeys(key), data, true)
	if err != nil {
		return nil, err
	}
	return unpad(raw)
}

// CbcEncrypt SM4-CBC + PKCS7。key/iv：16 字节。
func CbcEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("sm4: IV 必须为 16 字节")
	}
	rk := RoundKeys(key)
	padded := pad(data)
	out := make([]byte, len(padded))
	prev := iv
	for off := 0; off < len(padded); off += 16 {
		blk, _ := ecbRaw(rk, xor16(padded[off:off+16], prev), false)
		copy(out[off:], blk)
		prev = out[off : off+16]
	}
	return out, nil
}

// CbcDecrypt SM4-CBC 解密并去除 PKCS7 填充。
func CbcDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("sm4: IV 必须为 16 字节")
	}
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errors.New("sm4: 非法密文长度")
	}
	rk := RoundKeys(key)
	out := make([]byte, len(data))
	prev := make([]byte, 16)
	copy(prev, iv)
	for off := 0; off < len(data); off += 16 {
		blk, _ := ecbRaw(rk, data[off:off+16], true)
		copy(out[off:], xor16(blk, prev))
		copy(prev, data[off:off+16])
	}
	return unpad(out)
}

func main() {
	ok := true
	key, _ := hexDecode("0123456789abcdeffedcba9876543210")
	pt, _ := hexDecode("0123456789abcdeffedcba9876543210")
	want := "681edf34d206965e86b3e94f536e4246"
	got := fmt.Sprintf("%x", EcbEncrypt(key, pt)[:16])
	good := got == want
	ok = ok && good
	fmt.Printf("KAT1 ecb: %s got=%s\n", pass(good), got)
	// 往返 + 边界
	for _, n := range []int{0, 1, 15, 16, 17, 100} {
		data := make([]byte, n)
		rand.Read(data)
		k, iv := make([]byte, 16), make([]byte, 16)
		rand.Read(k)
		rand.Read(iv)
		b1, _ := EcbDecrypt(k, EcbEncrypt(k, data))
		b2, _ := CbcDecrypt(k, iv, must2(CbcEncrypt(k, iv, data)))
		ok = ok && bytes.Equal(b1, data) && bytes.Equal(b2, data)
	}
	// CBC 链式验证
	iv, _ := hexDecode("fedcba98765432100123456789abcdef")
	ct, _ := CbcEncrypt(key, iv, pt)
	ref := EcbEncrypt(key, xor16(pt, iv))
	good = fmt.Sprintf("%x", ct[:16]) == fmt.Sprintf("%x", ref[:16])
	ok = ok && good
	fmt.Printf("KAT  cbc-chain: %s\n", pass(good))
	// 100 万次迭代向量（GB/T 32907 示例2）
	rk := RoundKeys(key)
	x := append([]byte{}, pt...)
	for i := 0; i < 1000000; i++ {
		cryptBlock(rk, x, 0, x, 0)
	}
	good = fmt.Sprintf("%x", x) == "595298c7c6fd271f0402f804c33d3f66"
	ok = ok && good
	fmt.Printf("KAT2 1M-iterations: %s got=%x\n", pass(good), x)
	fmt.Println("ALL", pass(ok))
	if !ok {
		os.Exit(1)
	}
}

func pass(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}

func must2(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := hexVal(s[2*i]), hexVal(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("bad hex")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
