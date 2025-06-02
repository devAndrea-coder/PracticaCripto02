package util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ANDREA
 */
public class CryptoUtil {
    // ✅ CLAVE FIJA DE 16 CARACTERES (128 bits) - DEBE COINCIDIR CON EL FRONTEND
    private static final String SECRET_KEY = "mi_clave_secreta"; // Exactamente 16 caracteres
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static String encrypt(String plainText) throws Exception {
        if (plainText == null || plainText.trim().isEmpty()) {
            throw new IllegalArgumentException("Texto a cifrar no puede estar vacío");
        }

        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedText) throws Exception {
        if (encryptedText == null || encryptedText.trim().isEmpty()) {
            throw new IllegalArgumentException("Texto encriptado no puede estar vacío");
        }

        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        String password = "1234";
        try {
            String encrypted = encrypt(password);
            String decrypted = decrypt(encrypted);

            System.out.println("Original: " + password);
            System.out.println("Cifrado: " + encrypted);
            System.out.println("Descifrado: " + decrypted);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
