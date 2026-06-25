/* ========== RSA Implementation (Browser, BigInt-based) ========== */

/**
 * Pure-JavaScript RSA implementation using native BigInt.
 * Supports key generation (1024/2048/4096 bit), encryption, decryption,
 * and hybrid RSA+AES encryption for large messages.
 *
 * NOTE: This is an educational / demo implementation.
 * For production use, prefer the Web Crypto API (SubtleCrypto).
 */
const RSA = (() => {

  // ─── Math Utilities ───

  /** Modular exponentiation: (base^exp) mod m */
  function modPow(base, exp, m) {
    base = BigInt(base) % m;
    let result = 1n;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return result;
  }

  /** Extended GCD → returns { g, x, y } such that a*x + b*y = g */
  function extGcd(a, b) {
    if (a === 0n) return { g: b, x: 0n, y: 1n };
    const { g, x, y } = extGcd(b % a, a);
    return { g, x: y - (b / a) * x, y: x };
  }

  /** Modular inverse of a mod m */
  function modInverse(a, m) {
    let { g, x } = extGcd(a % m, m);
    if (g !== 1n) throw new Error('Modular inverse does not exist');
    return ((x % m) + m) % m;
  }

  /** Generate a cryptographically random BigInt of `bits` length */
  function randomBigInt(bits) {
    const bytes = Math.ceil(bits / 8);
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    // Set the top bit to ensure correct bit length
    arr[0] |= 0x80;
    // Set bottom bit to ensure odd
    arr[bytes - 1] |= 0x01;
    let n = 0n;
    for (const b of arr) n = (n << 8n) | BigInt(b);
    return n;
  }

  /** Miller-Rabin primality test */
  function millerRabin(n, k = 20) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n) return false;

    // Write n-1 as 2^r · d
    let r = 0n, d = n - 1n;
    while (d % 2n === 0n) { d /= 2n; r++; }

    // Witness loop
    for (let i = 0; i < k; i++) {
      // random a in [2, n-2]
      let a = 2n;
      if (n > 4n) {
        const range = n - 4n;
        const bits = range.toString(2).length;
        do { a = randomBigInt(bits) % range + 2n; } while (a >= n - 1n);
      }
      let x = modPow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let cont = false;
      for (let j = 0n; j < r - 1n; j++) {
        x = modPow(x, 2n, n);
        if (x === n - 1n) { cont = true; break; }
      }
      if (!cont) return false;
    }
    return true;
  }

  /** Generate a probable prime of `bits` length */
  function generatePrime(bits) {
    while (true) {
      const candidate = randomBigInt(bits);
      if (millerRabin(candidate, 20)) return candidate;
    }
  }

  // ─── Key Generation ───

  /**
   * Generate an RSA key pair.
   * @param {number} bits — Key size (1024, 2048, 4096)
   * @returns {{ publicKey: { n: string, e: string }, privateKey: { n: string, d: string }, bitLength: number }}
   */
  function generateKeyPair(bits = 2048) {
    const halfBits = Math.floor(bits / 2);
    const p = generatePrime(halfBits);
    let q;
    do { q = generatePrime(halfBits); } while (q === p);

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const e = 65537n;
    const d = modInverse(e, phi);

    return {
      publicKey:  { n: n.toString(), e: e.toString() },
      privateKey: { n: n.toString(), d: d.toString() },
      bitLength: bits
    };
  }

  // ─── Encryption / Decryption (raw, for small data) ───

  /** Convert string → BigInt (via UTF-8 hex) */
  function stringToBigInt(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    return BigInt('0x' + hex);
  }

  /** Convert BigInt → string (via hex → UTF-8) */
  function bigIntToString(n) {
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return new TextDecoder().decode(bytes);
  }

  /**
   * RSA encrypt (raw) — plaintext must be smaller than n.
   * @param {string} plaintext
   * @param {{ n: string, e: string }} publicKey
   * @returns {string} ciphertext (decimal string)
   */
  function encrypt(plaintext, publicKey) {
    const n = BigInt(publicKey.n);
    const e = BigInt(publicKey.e);
    const m = stringToBigInt(plaintext);
    if (m >= n) throw new Error('Message too long for this key size. Use hybrid encryption.');
    const c = modPow(m, e, n);
    return c.toString();
  }

  /**
   * RSA decrypt (raw).
   * @param {string} ciphertext — decimal string
   * @param {{ n: string, d: string }} privateKey
   * @returns {string} plaintext
   */
  function decrypt(ciphertext, privateKey) {
    const n = BigInt(privateKey.n);
    const d = BigInt(privateKey.d);
    const c = BigInt(ciphertext);
    const m = modPow(c, d, n);
    return bigIntToString(m);
  }

  // ─── Hybrid RSA + AES (for arbitrarily large messages) ───

  /**
   * Generate a random AES key (hex string of 32 chars = 128-bit).
   */
  function generateAESKey() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Hybrid encrypt: AES-encrypts the message, then RSA-encrypts the AES key.
   * Requires CryptoJS to be loaded.
   * @param {string} plaintext
   * @param {{ n: string, e: string }} publicKey
   * @returns {{ encryptedKey: string, encryptedData: string }}
   */
  function hybridEncrypt(plaintext, publicKey) {
    if (typeof CryptoJS === 'undefined') throw new Error('CryptoJS is required for hybrid encryption');
    const aesKey = generateAESKey();
    const encryptedData = CryptoJS.AES.encrypt(plaintext, aesKey).toString();
    const encryptedKey = encrypt(aesKey, publicKey);
    return { encryptedKey, encryptedData };
  }

  /**
   * Hybrid decrypt: RSA-decrypts the AES key, then AES-decrypts the message.
   * @param {{ encryptedKey: string, encryptedData: string }} payload
   * @param {{ n: string, d: string }} privateKey
   * @returns {string} plaintext
   */
  function hybridDecrypt(payload, privateKey) {
    if (typeof CryptoJS === 'undefined') throw new Error('CryptoJS is required for hybrid decryption');
    const aesKey = decrypt(payload.encryptedKey, privateKey);
    const decrypted = CryptoJS.AES.decrypt(payload.encryptedData, aesKey).toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('Decryption failed — wrong key or corrupted data');
    return decrypted;
  }

  // ─── PEM-like formatting helpers ───

  function formatPublicKeyPEM(pubKey) {
    const json = JSON.stringify(pubKey);
    const b64 = btoa(json);
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN RSA PUBLIC KEY-----\n${lines.join('\n')}\n-----END RSA PUBLIC KEY-----`;
  }

  function formatPrivateKeyPEM(privKey) {
    const json = JSON.stringify(privKey);
    const b64 = btoa(json);
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN RSA PRIVATE KEY-----\n${lines.join('\n')}\n-----END RSA PRIVATE KEY-----`;
  }

  function parsePublicKeyPEM(pem) {
    const b64 = pem.replace(/-----BEGIN RSA PUBLIC KEY-----/, '')
                   .replace(/-----END RSA PUBLIC KEY-----/, '')
                   .replace(/\s/g, '');
    return JSON.parse(atob(b64));
  }

  function parsePrivateKeyPEM(pem) {
    const b64 = pem.replace(/-----BEGIN RSA PRIVATE KEY-----/, '')
                   .replace(/-----END RSA PRIVATE KEY-----/, '')
                   .replace(/\s/g, '');
    return JSON.parse(atob(b64));
  }

  // ─── Public API ───
  return {
    generateKeyPair,
    encrypt,
    decrypt,
    hybridEncrypt,
    hybridDecrypt,
    formatPublicKeyPEM,
    formatPrivateKeyPEM,
    parsePublicKeyPEM,
    parsePrivateKeyPEM,
    // exposed for testing
    modPow,
    millerRabin,
    generatePrime
  };

})();
