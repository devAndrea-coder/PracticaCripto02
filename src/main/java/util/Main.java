/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package util;

/**
 *
 * @author USER
 */
public class Main {

    public static void main(String[] args) {
        String usuario = "kike";
        String token = JwtUtil.generarToken(usuario);

        System.out.println("🔐 Token generado:");
        System.out.println(token);

        System.out.println("\n✅ ¿Es válido?");
        System.out.println(JwtUtil.validarToken(token));

        System.out.println("\n👤 Usuario extraído del token:");
        System.out.println(JwtUtil.extraerEmail(token));
    }
}
