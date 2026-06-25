/* ========================================================================
   WebCrypto — Production-grade cryptography using the Web Crypto API
   ========================================================================
   Uses: RSA-OAEP (2048-bit), AES-GCM (256-bit), SHA-256
   This module coexists with the educational BigInt RSA in rsa.js.
   All operations are async and use window.crypto.subtle.
   ======================================================================== */

const WebCrypto = (() => {

  const subtle = window.crypto.subtle;

  // ═══════════════════════════════════════════════════════════════════════
  //  RSA-OAEP Key Generation (2048-bit, SHA-256)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Generate an RSA-OAEP key pair using the Web Crypto API.
   * @param {number} modulusLength — Key size in bits (default: 2048)
   * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
   */
  async function generateRSAKeyPair(modulusLength = 2048) {
    const keyPair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256'
      },
      true,  // extractable — needed for export
      ['encrypt', 'decrypt']
    );
    return keyPair;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RSA Key Export / Import (PEM format)
  // ═══════════════════════════════════════════════════════════════════════

  /** Convert an ArrayBuffer to a Base64 string */
  function ab2b64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /** Convert a Base64 string to an ArrayBuffer */
  function b642ab(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Export an RSA public key to PEM (SPKI format).
   * @param {CryptoKey} publicKey
   * @returns {Promise<string>} PEM string
   */
  async function exportPublicKeyPEM(publicKey) {
    const exported = await subtle.exportKey('spki', publicKey);
    const b64 = ab2b64(exported);
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  /**
   * Export an RSA private key to PEM (PKCS8 format).
   * @param {CryptoKey} privateKey
   * @returns {Promise<string>} PEM string
   */
  async function exportPrivateKeyPEM(privateKey) {
    const exported = await subtle.exportKey('pkcs8', privateKey);
    const b64 = ab2b64(exported);
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----`;
  }

  /**
   * Import an RSA public key from PEM (SPKI format).
   * @param {string} pem
   * @returns {Promise<CryptoKey>}
   */
  async function importPublicKeyPEM(pem) {
    const b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');
    const buffer = b642ab(b64);
    return subtle.importKey(
      'spki', buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  }

  /**
   * Import an RSA private key from PEM (PKCS8 format).
   * @param {string} pem
   * @returns {Promise<CryptoKey>}
   */
  async function importPrivateKeyPEM(pem) {
    const b64 = pem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, '');
    const buffer = b642ab(b64);
    return subtle.importKey(
      'pkcs8', buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RSA-OAEP Encrypt / Decrypt (for small data only — max ~190 bytes)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * RSA-OAEP encrypt a small message.
   * @param {string} plaintext
   * @param {CryptoKey} publicKey
   * @returns {Promise<string>} Base64 ciphertext
   */
  async function rsaEncrypt(plaintext, publicKey) {
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encoded
    );
    return ab2b64(encrypted);
  }

  /**
   * RSA-OAEP decrypt a small message.
   * @param {string} ciphertextB64 — Base64 encoded ciphertext
   * @param {CryptoKey} privateKey
   * @returns {Promise<string>} plaintext
   */
  async function rsaDecrypt(ciphertextB64, privateKey) {
    const buffer = b642ab(ciphertextB64);
    const decrypted = await subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      buffer
    );
    return new TextDecoder().decode(decrypted);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  AES-GCM (256-bit key, random 12-byte IV)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Generate a random AES-GCM 256-bit key.
   * @returns {Promise<CryptoKey>}
   */
  async function generateAESKey() {
    return subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,  // extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * AES-GCM encrypt.
   * @param {string} plaintext
   * @param {CryptoKey} aesKey
   * @returns {Promise<{ciphertext: string, iv: string}>} Base64 encoded
   */
  async function aesEncrypt(plaintext, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encoded
    );
    return {
      ciphertext: ab2b64(encrypted),
      iv: ab2b64(iv)
    };
  }

  /**
   * AES-GCM decrypt.
   * @param {string} ciphertextB64
   * @param {string} ivB64
   * @param {CryptoKey} aesKey
   * @returns {Promise<string>} plaintext
   */
  async function aesDecrypt(ciphertextB64, ivB64, aesKey) {
    const cipherBuffer = b642ab(ciphertextB64);
    const iv = new Uint8Array(b642ab(ivB64));
    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      cipherBuffer
    );
    return new TextDecoder().decode(decrypted);
  }

  /**
   * Export an AES key as raw bytes (for RSA wrapping).
   * @param {CryptoKey} aesKey
   * @returns {Promise<ArrayBuffer>}
   */
  async function exportAESKey(aesKey) {
    return subtle.exportKey('raw', aesKey);
  }

  /**
   * Import raw bytes as an AES-GCM key.
   * @param {ArrayBuffer} rawKey
   * @returns {Promise<CryptoKey>}
   */
  async function importAESKey(rawKey) {
    return subtle.importKey(
      'raw', rawKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Hybrid Encryption (RSA-OAEP + AES-GCM)
  //  — Encrypts large messages of any length —
  //
  //  Flow:
  //    Sender: Generate AES key → AES-GCM encrypt message → RSA-OAEP
  //            encrypt AES key → package as JSON
  //    Receiver: RSA-OAEP decrypt AES key → AES-GCM decrypt message
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Hybrid encrypt: AES-GCM encrypts the message, RSA-OAEP encrypts the AES key.
   * @param {string} plaintext
   * @param {CryptoKey} rsaPublicKey
   * @returns {Promise<object>} JSON-serializable package
   */
  async function hybridEncrypt(plaintext, rsaPublicKey) {
    // 1) Generate a random AES-256-GCM key
    const aesKey = await generateAESKey();

    // 2) Encrypt the message with AES-GCM
    const { ciphertext, iv } = await aesEncrypt(plaintext, aesKey);

    // 3) Export the AES key and encrypt it with RSA-OAEP
    const rawAESKey = await exportAESKey(aesKey);
    const encryptedKey = await subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaPublicKey,
      rawAESKey
    );

    return {
      mode: 'webcrypto-hybrid',
      encryptedKey: ab2b64(encryptedKey),
      ciphertext,
      iv,
      algorithm: 'RSA-OAEP + AES-256-GCM',
      hash: 'SHA-256'
    };
  }

  /**
   * Hybrid decrypt: RSA-OAEP decrypts the AES key, then AES-GCM decrypts the message.
   * @param {object} payload — { encryptedKey, ciphertext, iv }
   * @param {CryptoKey} rsaPrivateKey
   * @returns {Promise<string>} plaintext
   */
  async function hybridDecrypt(payload, rsaPrivateKey) {
    // 1) Decrypt the AES key with RSA-OAEP
    const encKeyBuffer = b642ab(payload.encryptedKey);
    const rawAESKey = await subtle.decrypt(
      { name: 'RSA-OAEP' },
      rsaPrivateKey,
      encKeyBuffer
    );

    // 2) Import the raw AES key
    const aesKey = await importAESKey(rawAESKey);

    // 3) Decrypt the message with AES-GCM
    return aesDecrypt(payload.ciphertext, payload.iv, aesKey);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  File Encryption (AES-GCM + RSA-OAEP for Key Wrapping)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Encrypt a binary file (ArrayBuffer).
   * Packages encrypted AES key, IV, and data into a single ArrayBuffer payload.
   * Format: [2 bytes: EncKeyLength] [EncKey] [12 bytes: IV] [Encrypted File Data]
   */
  async function encryptFile(fileBuffer, rsaPublicKey) {
    const aesKey = await generateAESKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt the file data
    const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, fileBuffer);
    
    // Export and wrap the AES key
    const rawAESKey = await exportAESKey(aesKey);
    const encryptedKey = await subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, rawAESKey);
    
    // Package it
    const encKeyLen = encryptedKey.byteLength;
    const pkg = new Uint8Array(2 + encKeyLen + 12 + encryptedData.byteLength);
    pkg[0] = (encKeyLen >> 8) & 0xFF;
    pkg[1] = encKeyLen & 0xFF;
    pkg.set(new Uint8Array(encryptedKey), 2);
    pkg.set(iv, 2 + encKeyLen);
    pkg.set(new Uint8Array(encryptedData), 2 + encKeyLen + 12);
    
    return pkg.buffer;
  }

  /**
   * Decrypt a binary file package.
   */
  async function decryptFile(pkgBuffer, rsaPrivateKey) {
    const pkg = new Uint8Array(pkgBuffer);
    if (pkg.length < 2) throw new Error("Invalid file package format.");
    
    const encKeyLen = (pkg[0] << 8) | pkg[1];
    if (pkg.length < 2 + encKeyLen + 12) throw new Error("File package is corrupted or truncated.");
    
    const encryptedKey = pkg.slice(2, 2 + encKeyLen);
    const iv = pkg.slice(2 + encKeyLen, 2 + encKeyLen + 12);
    const encryptedData = pkg.slice(2 + encKeyLen + 12);
    
    // Unwrap the AES key
    const rawAESKey = await subtle.decrypt({ name: 'RSA-OAEP' }, rsaPrivateKey, encryptedKey);
    const aesKey = await importAESKey(rawAESKey);
    
    // Decrypt the file
    const decryptedData = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encryptedData);
    return decryptedData;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Digital Signatures (RSA-PSS + SHA-256)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Generate an RSA-PSS key pair for signing/verification.
   * @param {number} modulusLength
   * @returns {Promise<CryptoKeyPair>}
   */
  async function generateSigningKeyPair(modulusLength = 2048) {
    return subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
  }

  /**
   * Sign a message with RSA-PSS.
   * @param {string} message
   * @param {CryptoKey} privateKey — RSA-PSS private key
   * @returns {Promise<string>} Base64 signature
   */
  async function sign(message, privateKey) {
    const encoded = new TextEncoder().encode(message);
    const signature = await subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      privateKey,
      encoded
    );
    return ab2b64(signature);
  }

  /**
   * Verify a message signature with RSA-PSS.
   * @param {string} message
   * @param {string} signatureB64
   * @param {CryptoKey} publicKey — RSA-PSS public key
   * @returns {Promise<boolean>}
   */
  async function verify(message, signatureB64, publicKey) {
    const encoded = new TextEncoder().encode(message);
    const sigBuffer = b642ab(signatureB64);
    return subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      publicKey,
      sigBuffer,
      encoded
    );
  }

  /**
   * Export a signing public key to PEM (SPKI).
   * @param {CryptoKey} publicKey
   * @returns {Promise<string>}
   */
  async function exportSigningPublicKeyPEM(publicKey) {
    const exported = await subtle.exportKey('spki', publicKey);
    const b64 = ab2b64(exported);
    const lines = b64.match(/.{1,64}/g) || [b64];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  SHA-256 Integrity Hashing
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Compute SHA-256 hash of a string.
   * @param {string} message
   * @returns {Promise<string>} hex digest
   */
  async function sha256(message) {
    const encoded = new TextEncoder().encode(message);
    const hashBuffer = await subtle.digest('SHA-256', encoded);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Compute SHA-256 hash of an ArrayBuffer (e.g. file contents).
   * @param {ArrayBuffer} buffer
   * @returns {Promise<string>} hex digest
   */
  async function sha256Buffer(buffer) {
    const hashBuffer = await subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Utility: Timing wrapper for performance measurement
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Run an async function and measure its execution time.
   * @param {Function} fn — async function
   * @returns {Promise<{result: any, elapsed: number}>} elapsed in ms
   */
  async function timed(fn) {
    const start = performance.now();
    const result = await fn();
    const elapsed = performance.now() - start;
    return { result, elapsed };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Public API
  // ═══════════════════════════════════════════════════════════════════════

  return {
    // RSA-OAEP key management
    generateRSAKeyPair,
    exportPublicKeyPEM,
    exportPrivateKeyPEM,
    importPublicKeyPEM,
    importPrivateKeyPEM,

    // RSA-OAEP encrypt/decrypt (small data)
    rsaEncrypt,
    rsaDecrypt,

    // AES-GCM
    generateAESKey,
    aesEncrypt,
    aesDecrypt,
    exportAESKey,
    importAESKey,

    // Hybrid RSA-OAEP + AES-GCM
    hybridEncrypt,
    hybridDecrypt,
    
    // File Encryption
    encryptFile,
    decryptFile,

    // Digital signatures (RSA-PSS)
    generateSigningKeyPair,
    sign,
    verify,
    exportSigningPublicKeyPEM,

    // SHA-256
    sha256,
    sha256Buffer,

    // Utilities
    timed,
    ab2b64,
    b642ab
  };

})();
