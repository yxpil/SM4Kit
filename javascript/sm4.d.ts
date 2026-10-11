/** SM4Kit · TypeScript 类型定义（配合 sm4.js 使用） */
export declare function roundKeys(key: Uint8Array): number[];
export declare function ecbEncrypt(key: Uint8Array, data: Uint8Array): Uint8Array;
export declare function ecbDecrypt(key: Uint8Array, data: Uint8Array): Uint8Array;
export declare function cbcEncrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
export declare function cbcDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
export declare function selfTest(longMode?: boolean): boolean;
