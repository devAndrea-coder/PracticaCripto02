package util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author USER
 */
public class JwtUtil {
     // Clave secreta para firmar los tokens (en producción debe estar en variables de entorno)
    private static final String SECRET_KEY = "MiClaveSecretaSuperSeguraParaJWT2024CriptoPractica123456789";
    private static final long EXPIRATION_TIME = 86400000; // 24 horas en milisegundos
    
    // Generar la clave de firma
    private static Key getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }
    
    /**
     * Genera un token JWT para el usuario
     * @param email Email del usuario
     * @return Token JWT generado
     */
    public static String generarToken(String email) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("email", email);
            claims.put("loginMethod", "google");
            
            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(email)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();
                    
        } catch (Exception e) {
            System.err.println("ERROR - Error al generar token JWT: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al generar token JWT", e);
        }
    }
    
    /**
     * Genera un token JWT con información adicional
     * @param email Email del usuario
     * @param name Nombre del usuario
     * @return Token JWT generado
     */
    public static String generarToken(String email, String name) {
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("email", email);
            claims.put("name", name);
            claims.put("loginMethod", "google");
            
            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(email)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                    .compact();
                    
        } catch (Exception e) {
            System.err.println("ERROR - Error al generar token JWT: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al generar token JWT", e);
        }
    }
    
    /**
     * Valida un token JWT
     * @param token Token a validar
     * @return true si el token es válido, false en caso contrario
     */
    public static boolean validarToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            System.out.println("DEBUG - Token inválido: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Extrae el email del token JWT
     * @param token Token JWT
     * @return Email del usuario
     */
    public static String extraerEmail(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            System.err.println("ERROR - Error al extraer email del token: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Extrae las claims del token JWT
     * @param token Token JWT
     * @return Claims del token
     */
    public static Claims extraerClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            System.err.println("ERROR - Error al extraer claims del token: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Verifica si el token ha expirado
     * @param token Token JWT
     * @return true si ha expirado, false en caso contrario
     */
    public static boolean esTokenExpirado(String token) {
        try {
            Claims claims = extraerClaims(token);
            if (claims != null) {
                return claims.getExpiration().before(new Date());
            }
            return true;
        } catch (Exception e) {
            System.err.println("ERROR - Error al verificar expiración del token: " + e.getMessage());
            return true;
        }
    }
}
