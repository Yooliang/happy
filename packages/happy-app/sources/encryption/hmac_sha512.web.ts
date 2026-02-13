// Pure JS SHA-512 + HMAC for Web (no crypto.subtle on HTTP)

const K = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
];

function add64(ah: number, al: number, bh: number, bl: number): [number, number] {
    const lo = (al + bl) >>> 0;
    const hi = (ah + bh + ((lo < al) ? 1 : 0)) >>> 0;
    return [hi, lo];
}

function rotr64(h: number, l: number, n: number): [number, number] {
    if (n < 32) {
        return [(h >>> n | l << (32 - n)) >>> 0, (l >>> n | h << (32 - n)) >>> 0];
    }
    n -= 32;
    return [(l >>> n | h << (32 - n)) >>> 0, (h >>> n | l << (32 - n)) >>> 0];
}

function shr64(h: number, l: number, n: number): [number, number] {
    if (n < 32) {
        return [(h >>> n) >>> 0, (l >>> n | h << (32 - n)) >>> 0];
    }
    return [0, (h >>> (n - 32)) >>> 0];
}

function sha512(data: Uint8Array): Uint8Array {
    let h0h = 0x6a09e667, h0l = 0xf3bcc908;
    let h1h = 0xbb67ae85, h1l = 0x84caa73b;
    let h2h = 0x3c6ef372, h2l = 0xfe94f82b;
    let h3h = 0xa54ff53a, h3l = 0x5f1d36f1;
    let h4h = 0x510e527f, h4l = 0xade682d1;
    let h5h = 0x9b05688c, h5l = 0x2b3e6c1f;
    let h6h = 0x1f83d9ab, h6l = 0xfb41bd6b;
    let h7h = 0x5be0cd19, h7l = 0x137e2179;

    // Pre-processing: adding padding bits
    const bitLen = data.length * 8;
    const padLen = ((128 - ((data.length + 17) % 128)) % 128) + 17;
    const padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    padded[data.length] = 0x80;
    // Length in bits as 128-bit big-endian (we only use low 64 bits)
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 4, bitLen >>> 0, false);
    view.setUint32(padded.length - 8, (bitLen / 0x100000000) >>> 0, false);

    const wh = new Int32Array(80);
    const wl = new Int32Array(80);

    for (let offset = 0; offset < padded.length; offset += 128) {
        for (let i = 0; i < 16; i++) {
            wh[i] = view.getInt32(offset + i * 8, false);
            wl[i] = view.getInt32(offset + i * 8 + 4, false);
        }
        for (let i = 16; i < 80; i++) {
            // s0 = rotr(w[i-15], 1) ^ rotr(w[i-15], 8) ^ shr(w[i-15], 7)
            const [a1h, a1l] = rotr64(wh[i - 15], wl[i - 15], 1);
            const [a2h, a2l] = rotr64(wh[i - 15], wl[i - 15], 8);
            const [a3h, a3l] = shr64(wh[i - 15], wl[i - 15], 7);
            const s0h = (a1h ^ a2h ^ a3h) >>> 0;
            const s0l = (a1l ^ a2l ^ a3l) >>> 0;

            // s1 = rotr(w[i-2], 19) ^ rotr(w[i-2], 61) ^ shr(w[i-2], 6)
            const [b1h, b1l] = rotr64(wh[i - 2], wl[i - 2], 19);
            const [b2h, b2l] = rotr64(wh[i - 2], wl[i - 2], 61);
            const [b3h, b3l] = shr64(wh[i - 2], wl[i - 2], 6);
            const s1h = (b1h ^ b2h ^ b3h) >>> 0;
            const s1l = (b1l ^ b2l ^ b3l) >>> 0;

            let [rh, rl] = add64(wh[i - 16], wl[i - 16], s0h, s0l);
            [rh, rl] = add64(rh, rl, wh[i - 7], wl[i - 7]);
            [rh, rl] = add64(rh, rl, s1h, s1l);
            wh[i] = rh;
            wl[i] = rl;
        }

        let ah = h0h, al = h0l;
        let bh = h1h, bl = h1l;
        let ch = h2h, cl = h2l;
        let dh = h3h, dl = h3l;
        let eh = h4h, el = h4l;
        let fh = h5h, fl = h5l;
        let gh = h6h, gl = h6l;
        let hh = h7h, hl = h7l;

        for (let i = 0; i < 80; i++) {
            // S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
            const [e14h, e14l] = rotr64(eh, el, 14);
            const [e18h, e18l] = rotr64(eh, el, 18);
            const [e41h, e41l] = rotr64(eh, el, 41);
            const S1h = (e14h ^ e18h ^ e41h) >>> 0;
            const S1l = (e14l ^ e18l ^ e41l) >>> 0;

            // ch = (e & f) ^ (~e & g)
            const chh = ((eh & fh) ^ (~eh & gh)) >>> 0;
            const chl = ((el & fl) ^ (~el & gl)) >>> 0;

            // temp1 = h + S1 + ch + K[i] + w[i]
            let [t1h, t1l] = add64(hh, hl, S1h, S1l);
            [t1h, t1l] = add64(t1h, t1l, chh, chl);
            [t1h, t1l] = add64(t1h, t1l, K[i * 2], K[i * 2 + 1]);
            [t1h, t1l] = add64(t1h, t1l, wh[i], wl[i]);

            // S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
            const [a28h, a28l] = rotr64(ah, al, 28);
            const [a34h, a34l] = rotr64(ah, al, 34);
            const [a39h, a39l] = rotr64(ah, al, 39);
            const S0h = (a28h ^ a34h ^ a39h) >>> 0;
            const S0l = (a28l ^ a34l ^ a39l) >>> 0;

            // maj = (a & b) ^ (a & c) ^ (b & c)
            const majh = ((ah & bh) ^ (ah & ch) ^ (bh & ch)) >>> 0;
            const majl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;

            const [t2h, t2l] = add64(S0h, S0l, majh, majl);

            hh = gh; hl = gl;
            gh = fh; gl = fl;
            fh = eh; fl = el;
            [eh, el] = add64(dh, dl, t1h, t1l);
            dh = ch; dl = cl;
            ch = bh; cl = bl;
            bh = ah; bl = al;
            [ah, al] = add64(t1h, t1l, t2h, t2l);
        }

        [h0h, h0l] = add64(h0h, h0l, ah, al);
        [h1h, h1l] = add64(h1h, h1l, bh, bl);
        [h2h, h2l] = add64(h2h, h2l, ch, cl);
        [h3h, h3l] = add64(h3h, h3l, dh, dl);
        [h4h, h4l] = add64(h4h, h4l, eh, el);
        [h5h, h5l] = add64(h5h, h5l, fh, fl);
        [h6h, h6l] = add64(h6h, h6l, gh, gl);
        [h7h, h7l] = add64(h7h, h7l, hh, hl);
    }

    const result = new Uint8Array(64);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0h); rv.setUint32(4, h0l);
    rv.setUint32(8, h1h); rv.setUint32(12, h1l);
    rv.setUint32(16, h2h); rv.setUint32(20, h2l);
    rv.setUint32(24, h3h); rv.setUint32(28, h3l);
    rv.setUint32(32, h4h); rv.setUint32(36, h4l);
    rv.setUint32(40, h5h); rv.setUint32(44, h5l);
    rv.setUint32(48, h6h); rv.setUint32(52, h6l);
    rv.setUint32(56, h7h); rv.setUint32(60, h7l);
    return result;
}

export async function hmac_sha512(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const blockSize = 128;

    let actualKey = key;
    if (key.length > blockSize) {
        actualKey = sha512(key);
    }

    const paddedKey = new Uint8Array(blockSize);
    paddedKey.set(actualKey);

    const innerKey = new Uint8Array(blockSize);
    const outerKey = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        innerKey[i] = paddedKey[i] ^ 0x36;
        outerKey[i] = paddedKey[i] ^ 0x5c;
    }

    const innerData = new Uint8Array(blockSize + data.length);
    innerData.set(innerKey);
    innerData.set(data, blockSize);
    const innerHash = sha512(innerData);

    const outerData = new Uint8Array(blockSize + 64);
    outerData.set(outerKey);
    outerData.set(innerHash, blockSize);
    return sha512(outerData);
}
