/* ========== Robust LSB Steganography Engine ========== */

const Stego = (() => {

  // Magic header to detect valid stego data: "STG1" (4 bytes = 32 bits)
  // "01010011 01010100 01000111 00110001"
  const MAGIC_BITS = "01010011010101000100011100110001";

  // Helper: Pad binary string to 32 bits
  function numberToBinary32(num) {
    return num.toString(2).padStart(32, '0');
  }

  /**
   * Calculate maximum string payload capacity in bytes.
   */
  function calculateCapacityBytes(width, height) {
    // Total pixels * 3 channels (RGB) / 8 bits = max bytes
    // Minus 4 bytes for magic, 4 bytes for length
    const totalBits = width * height * 3;
    const capacityBytes = Math.floor((totalBits - 64) / 8);
    return Math.max(0, capacityBytes);
  }

  /**
   * Embed data string into an image using LSB (Least Significant Bit).
   * Format: [MAGIC 32 bits] + [LENGTH 32 bits] + [PAYLOAD bytes]
   */
  function embedData(canvas, img, dataStr) {
    const ctx = canvas.getContext('2d');
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;

    // Encode string to UTF-8 bytes to safely handle all characters
    const encoder = new TextEncoder();
    const bytes = encoder.encode(dataStr);
    
    // Construct full bitstream
    let payloadBits = '';
    for (let b of bytes) {
      payloadBits += b.toString(2).padStart(8, '0');
    }

    const lengthBits = numberToBinary32(bytes.length);
    const fullStream = MAGIC_BITS + lengthBits + payloadBits;

    const maxCapacityBits = (data.length / 4) * 3;
    if (fullStream.length > maxCapacityBits) {
      return { 
        ok: false, 
        reason: `Payload too large. Needs ${fullStream.length} bits, but image only has ${maxCapacityBits} bits.` 
      };
    }

    let bitIdx = 0;
    for (let i = 0; i < data.length && bitIdx < fullStream.length; i++) {
      // Skip alpha channel (every 4th byte)
      if ((i + 1) % 4 === 0) continue;
      
      // Clear LSB and set to bitstream value
      data[i] = (data[i] & 0xFE) | parseInt(fullStream[bitIdx], 10);
      bitIdx++;
    }

    ctx.putImageData(imageData, 0, 0);
    return { ok: true, bitsUsed: bitIdx, capacityBytes: calculateCapacityBytes(img.width, img.height) };
  }

  /**
   * Extract data string from an image using LSB.
   * Throws an Error if no valid payload is found.
   */
  function extractData(img) {
    const c = document.createElement('canvas');
    c.width = img.width;
    c.height = img.height;
    const ctx = c.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const data = ctx.getImageData(0, 0, c.width, c.height).data;

    let extractedBits = '';
    
    // Phase 1: Read the first 64 bits (Magic + Length)
    for (let i = 0; i < data.length; i++) {
      if ((i + 1) % 4 === 0) continue;
      extractedBits += (data[i] & 1).toString();
      if (extractedBits.length === 64) break;
    }

    if (extractedBits.length < 64) {
      throw new Error("Image is too small to contain valid steganography data.");
    }

    const magic = extractedBits.substring(0, 32);
    if (magic !== MAGIC_BITS) {
      throw new Error("No secure steganographic signature found in this image.");
    }

    const lengthBits = extractedBits.substring(32, 64);
    const dataLengthBytes = parseInt(lengthBits, 2);
    const dataLengthBits = dataLengthBytes * 8;

    // Phase 2: Extract the actual payload bits
    const totalBitsNeeded = 64 + dataLengthBits;
    const maxCapacityBits = (data.length / 4) * 3;
    
    if (totalBitsNeeded > maxCapacityBits) {
      throw new Error(`Corrupted header: declares length ${dataLengthBytes} bytes, which exceeds image capacity.`);
    }

    // Reset and read exactly what's needed
    extractedBits = '';
    for (let i = 0; i < data.length && extractedBits.length < totalBitsNeeded; i++) {
      if ((i + 1) % 4 === 0) continue;
      extractedBits += (data[i] & 1).toString();
    }

    const payloadBits = extractedBits.substring(64);
    
    // Convert bits back to UTF-8 bytes
    const payloadBytes = new Uint8Array(dataLengthBytes);
    for (let i = 0; i < dataLengthBytes; i++) {
      const byteStr = payloadBits.substring(i * 8, i * 8 + 8);
      payloadBytes[i] = parseInt(byteStr, 2);
    }

    const decoder = new TextDecoder();
    return decoder.decode(payloadBytes);
  }

  return { embedData, extractData, calculateCapacityBytes };
})();
