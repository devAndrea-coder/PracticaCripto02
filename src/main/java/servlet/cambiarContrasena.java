package servlet;

import dao.ClienteJpaController;
import dto.Cliente;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONObject;
import util.CryptoUtil;
import util.HashUtil;

/**
 *
 * @author ANDREA
 */
@WebServlet(name = "cambiarContrasena", urlPatterns = {"/contrasena"})
public class cambiarContrasena extends HttpServlet {
    
    private ClienteJpaController clienteService;
    private EntityManagerFactory emf = Persistence.createEntityManagerFactory("com.mycompany_CriptoPractica02_war_1.0-SNAPSHOTPU");

    @Override
    public void init() throws ServletException {
        super.init();
        clienteService = new ClienteJpaController(emf);
    }

    @Override
    public void destroy() {
        if (emf != null) {
            emf.close();
        }
        super.destroy();
    }

    // CONFIGURAR HEADERS CORS
    private void configurarCORS(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        configurarCORS(response);
        response.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        configurarCORS(response);
        PrintWriter out = response.getWriter();

        try {
            // OBTENER PARÁMETROS CIFRADOS
            String login = request.getParameter("login");
            String claveActualCifrada = request.getParameter("claveActual");
            String nuevaClaveCifrada = request.getParameter("nuevaClave");

            // VALIDAR CAMPOS REQUERIDOS
            if (login == null || login.trim().isEmpty()) {
                System.out.println("❌ ERROR: Login faltante");
                enviarError(out, "El campo login es obligatorio");
                return;
            }

            if (claveActualCifrada == null || claveActualCifrada.trim().isEmpty()) {
                System.out.println("❌ ERROR: Clave actual cifrada faltante");
                enviarError(out, "La contraseña actual es obligatoria");
                return;
            }

            if (nuevaClaveCifrada == null || nuevaClaveCifrada.trim().isEmpty()) {
                System.out.println("❌ ERROR: Nueva clave cifrada faltante");
                enviarError(out, "La nueva contraseña es obligatoria");
                return;
            }

            // ✅ PASO 1: DESCIFRAR CONTRASEÑAS RECIBIDAS DEL FRONTEND
            String claveActualDescifrada;
            String nuevaClaveDescifrada;
            
            try {
                System.out.println("🔓 Descifrando contraseñas recibidas...");
                claveActualDescifrada = CryptoUtil.decrypt(claveActualCifrada.trim());
                nuevaClaveDescifrada = CryptoUtil.decrypt(nuevaClaveCifrada.trim());
                System.out.println("✅ Contraseñas descifradas exitosamente");
                
                // Validar que no estén vacías después del descifrado
                if (claveActualDescifrada == null || claveActualDescifrada.trim().isEmpty()) {
                    System.out.println("❌ ERROR: Contraseña actual vacía después del descifrado");
                    enviarError(out, "Error al procesar la contraseña actual");
                    return;
                }
                
                if (nuevaClaveDescifrada == null || nuevaClaveDescifrada.trim().isEmpty()) {
                    System.out.println("❌ ERROR: Nueva contraseña vacía después del descifrado");
                    enviarError(out, "Error al procesar la nueva contraseña");
                    return;
                }
                
            } catch (Exception e) {
                System.out.println("❌ ERROR al descifrar contraseñas: " + e.getMessage());
                e.printStackTrace();
                enviarError(out, "Error al procesar las contraseñas cifradas");
                return;
            }

            // VALIDAR LONGITUD DE NUEVA CONTRASEÑA
            if (nuevaClaveDescifrada.trim().length() < 4) {
                System.out.println("❌ ERROR: Nueva contraseña muy corta");
                enviarError(out, "La nueva contraseña debe tener al menos 4 caracteres");
                return;
            }

            // ✅ PASO 2: BUSCAR CLIENTE POR LOGIN
            List<Cliente> clientes = clienteService.findClienteEntities();
            Cliente cliente = null;

            for (Cliente c : clientes) {
                if (c.getLogiClie() != null && c.getLogiClie().equals(login.trim())) {
                    cliente = c;
                    break;
                }
            }

            if (cliente == null) {
                System.out.println("❌ ERROR: Cliente no encontrado - " + login);
                enviarError(out, "Usuario no encontrado");
                return;
            }

            System.out.println("✅ Cliente encontrado: " + cliente.getLogiClie());

            // ✅ PASO 3: VERIFICAR CONTRASEÑA ACTUAL USANDO SHA-256 + SALT
            String hashActualAlmacenado = cliente.getPassClie(); // Hash SHA-256 almacenado en BD
            
            try {
                System.out.println("🔍 Verificando contraseña actual con SHA-256...");
                boolean passwordValida = HashUtil.verifyPassword(claveActualDescifrada.trim(), hashActualAlmacenado);
                
                if (!passwordValida) {
                    System.out.println("❌ ERROR: Contraseña actual incorrecta");
                    enviarError(out, "La contraseña actual es incorrecta");
                    return;
                }
                
                System.out.println("✅ Contraseña actual verificada correctamente");
                
            } catch (Exception e) {
                System.out.println("❌ ERROR al verificar contraseña actual: " + e.getMessage());
                e.printStackTrace();
                enviarError(out, "Error al verificar la contraseña actual");
                return;
            }

            // VALIDAR QUE LA NUEVA CONTRASEÑA SEA DIFERENTE
            if (claveActualDescifrada.trim().equals(nuevaClaveDescifrada.trim())) {
                System.out.println("❌ ERROR: Nueva contraseña igual a la actual");
                enviarError(out, "La nueva contraseña debe ser diferente a la actual");
                return;
            }

            // ✅ PASO 4: GENERAR HASH SHA-256 DE LA NUEVA CONTRASEÑA
            String nuevoHashPassword;
            
            try {
                System.out.println("🔐 Generando hash SHA-256 para nueva contraseña...");
                nuevoHashPassword = HashUtil.hashPassword(nuevaClaveDescifrada.trim());
                System.out.println("✅ Hash SHA-256 generado exitosamente");
                System.out.println("🔒 Nuevo hash: " + nuevoHashPassword.substring(0, 20) + "...");
                
            } catch (Exception e) {
                System.out.println("❌ ERROR al generar hash SHA-256: " + e.getMessage());
                e.printStackTrace();
                enviarError(out, "Error al procesar la nueva contraseña");
                return;
            }

            // ✅ PASO 5: ACTUALIZAR CONTRASEÑA EN BASE DE DATOS
            try {
                cliente.setPassClie(nuevoHashPassword);
                clienteService.edit(cliente);
                
                System.out.println("✅ Contraseña actualizada exitosamente para usuario: " + login);
                System.out.println("🔐 Nueva contraseña almacenada con hash SHA-256 + salt");
                
            } catch (Exception e) {
                System.out.println("❌ ERROR al actualizar en base de datos: " + e.getMessage());
                e.printStackTrace();
                enviarError(out, "Error al actualizar la contraseña en la base de datos");
                return;
            }

            // ✅ ENVIAR RESPUESTA EXITOSA
            JSONObject successJson = new JSONObject();
            successJson.put("success", true);
            successJson.put("message", "Contraseña cambiada exitosamente");
            successJson.put("security", "Contraseña cifrada con AES y almacenada con hash SHA-256");
            
            out.print(successJson.toString());
            out.flush();

            System.out.println("🎉 Cambio de contraseña completado exitosamente");

        } catch (Exception e) {
            System.out.println("❌ ERROR INTERNO GENERAL: " + e.getMessage());
            e.printStackTrace();

            JSONObject errorJson = new JSONObject();
            errorJson.put("success", false);
            errorJson.put("message", "Error interno del servidor. Por favor, intente nuevamente.");
            errorJson.put("technical", "Error en proceso de cifrado/descifrado o hash");
            
            out.print(errorJson.toString());
            out.flush();
        }
    }

    /**
     * Método auxiliar para enviar errores de forma consistente
     */
    private void enviarError(PrintWriter out, String mensaje) {
        try {
            JSONObject errorJson = new JSONObject();
            errorJson.put("success", false);
            errorJson.put("message", mensaje);
            errorJson.put("timestamp", System.currentTimeMillis());
            
            out.print(errorJson.toString());
            out.flush();
            
        } catch (Exception e) {
            System.out.println("❌ ERROR al enviar respuesta de error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
