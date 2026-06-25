/*
=========================================================
 Secure Steganography + RSA + Watermarking Project
 Java Core Logic
=========================================================

FEATURES:
1. RSA Key Generation
2. RSA Encrypt / Decrypt
3. AES Hybrid Encryption
4. LSB Image Steganography
5. Image Watermarking

REQUIRED:
- Java 17+
- No external libraries needed
=========================================================
*/

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import javax.imageio.ImageIO;

public class SecureStegoProject {

    // =====================================================
    // RSA SECTION
    // =====================================================

    public static KeyPair generateRSAKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.generateKeyPair();
    }

    public static String rsaEncrypt(String message, PublicKey publicKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String rsaDecrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decrypted = cipher.doFinal(
                Base64.getDecoder().decode(encryptedMessage));

        return new String(decrypted);
    }

    // =====================================================
    // AES HYBRID ENCRYPTION
    // =====================================================

    public static SecretKey generateAESKey() throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);

        return generator.generateKey();
    }

    public static String aesEncrypt(String message, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String aesDecrypt(String encryptedMessage, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decrypted = cipher.doFinal(
                Base64.getDecoder().decode(encryptedMessage));

        return new String(decrypted);
    }

    // =====================================================
    // WATERMARKING
    // =====================================================

    public static void addWatermark(
            String inputImage,
            String outputImage,
            String watermarkText) throws Exception {

        BufferedImage image = ImageIO.read(new File(inputImage));

        Graphics2D g2d = image.createGraphics();

        g2d.setFont(new Font("Arial", Font.BOLD, 40));

        g2d.setColor(new Color(255, 255, 255, 120));

        int x = image.getWidth() - 250;
        int y = image.getHeight() - 40;

        g2d.drawString(watermarkText, x, y);

        g2d.dispose();

        ImageIO.write(image, "png", new File(outputImage));

        System.out.println("Watermark Added Successfully!");
    }

    // =====================================================
    // STEGANOGRAPHY (LSB)
    // =====================================================

    public static void hideMessage(
            String imagePath,
            String outputPath,
            String secretMessage) throws Exception {

        BufferedImage image = ImageIO.read(new File(imagePath));

        byte[] messageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);

        int messageLength = messageBytes.length;

        int width = image.getWidth();

        int height = image.getHeight();

        int messageIndex = 0;
        int bitIndex = 0;

        outerLoop: for (int y = 0; y < height; y++) {

            for (int x = 0; x < width; x++) {

                int pixel = image.getRGB(x, y);

                int alpha = (pixel >> 24) & 0xff;
                int red = (pixel >> 16) & 0xff;
                int green = (pixel >> 8) & 0xff;
                int blue = pixel & 0xff;

                if (messageIndex < messageLength) {

                    int bit = (messageBytes[messageIndex] >> (7 - bitIndex)) & 1;

                    blue = (blue & 0xFE) | bit;

                    bitIndex++;

                    if (bitIndex == 8) {
                        bitIndex = 0;
                        messageIndex++;
                    }

                } else {
                    break outerLoop;
                }

                int newPixel = (alpha << 24) |
                        (red << 16) |
                        (green << 8) |
                        blue;

                image.setRGB(x, y, newPixel);
            }
        }

        ImageIO.write(image, "png", new File(outputPath));

        System.out.println("Message Hidden Successfully!");
    }

    // =====================================================
    // EXTRACT MESSAGE
    // =====================================================

    public static String extractMessage(
            String imagePath,
            int messageLength) throws Exception {

        BufferedImage image = ImageIO.read(new File(imagePath));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        int width = image.getWidth();

        int height = image.getHeight();

        int currentByte = 0;
        int bitCount = 0;

        int extractedBytes = 0;

        outerLoop: for (int y = 0; y < height; y++) {

            for (int x = 0; x < width; x++) {

                int pixel = image.getRGB(x, y);

                int blue = pixel & 0xff;

                int bit = blue & 1;

                currentByte = (currentByte << 1) | bit;

                bitCount++;

                if (bitCount == 8) {

                    baos.write(currentByte);

                    extractedBytes++;

                    bitCount = 0;
                    currentByte = 0;

                    if (extractedBytes == messageLength) {
                        break outerLoop;
                    }
                }
            }
        }

        return baos.toString(StandardCharsets.UTF_8.name());
    }

    // =====================================================
    // MAIN METHOD
    // =====================================================

    public static void main(String[] args) {

        try {

            // ==========================
            // RSA
            // ==========================

            KeyPair keyPair = generateRSAKeys();

            String originalMessage = "Hello Secure World";

            String encryptedRSA = rsaEncrypt(originalMessage, keyPair.getPublic());

            String decryptedRSA = rsaDecrypt(encryptedRSA, keyPair.getPrivate());

            System.out.println("RSA Encrypted:");
            System.out.println(encryptedRSA);

            System.out.println("\nRSA Decrypted:");
            System.out.println(decryptedRSA);

            // ==========================
            // AES
            // ==========================

            SecretKey aesKey = generateAESKey();

            String aesEncrypted = aesEncrypt(originalMessage, aesKey);

            String aesDecrypted = aesDecrypt(aesEncrypted, aesKey);

            System.out.println("\nAES Encrypted:");
            System.out.println(aesEncrypted);

            System.out.println("\nAES Decrypted:");
            System.out.println(aesDecrypted);

            // ==========================
            // WATERMARK
            // ==========================

            addWatermark(
                    "input.png",
                    "watermarked.png",
                    "© SecureProject");

            // ==========================
            // STEGANOGRAPHY
            // ==========================

            hideMessage(
                    "input.png",
                    "stego.png",
                    "Hidden Secret Message");

            String extracted = extractMessage("stego.png", 21);

            System.out.println("\nExtracted Message:");
            System.out.println(extracted);

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}