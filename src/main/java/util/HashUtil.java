package util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 * @author ANDREA
 */
public class HashUtil {
      private static final String SALT = "mi_salt_secreto_2025";
    private static final String ALGORITHM = "SHA-256";

    // Genera un hash con SHA-256 usando un salt fijo
    public static String hashPassword(String password) {
        if (password == null) throw new IllegalArgumentException("Password no puede ser null");
        String input = password + SALT;
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algoritmo no disponible", e);
        }
    }

    // Verifica si el password coincide con el hash guardado
    public static boolean verifyPassword(String password, String storedHash) {
        if (password == null || storedHash == null) return false;
        return hashPassword(password).equals(storedHash);
    }

    // Convierte un array de bytes a string hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            String h = Integer.toHexString(0xff & b);
            if (h.length() == 1) hex.append('0');
            hex.append(h);
        }
        return hex.toString();
    }

    // Genera un salt aleatorio
    public static String generateRandomSalt(int length) {
        byte[] salt = new byte[length];
        new SecureRandom().nextBytes(salt);
        return bytesToHex(salt);
    }

    // Hash con un salt personalizado
    public static String hashPasswordWithCustomSalt(String password, String customSalt) {
        if (password == null || customSalt == null) throw new IllegalArgumentException();
        String input = password + customSalt;
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            return bytesToHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Prueba de rendimiento
    public static void performanceTest(int iterations, String password) {
        long start = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            hashPassword(password + i);
        }
        long end = System.currentTimeMillis();
        double avg = (end - start) / (double) iterations;
        System.out.println("Tiempo promedio por hash: " + String.format("%.2f", avg) + " ms");
    }

    // Ejemplo de uso
    public static void main(String[] args) {
        String password = "1234";
        String hash = hashPassword(password);
        System.out.println("Hash generado: " + hash);
        System.out.println("Verificación: " + verifyPassword("1234", hash)); // true
    }
}
