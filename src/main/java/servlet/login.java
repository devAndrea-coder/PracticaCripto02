package servlet;

import dao.ClienteJpaController;
import dto.Cliente;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
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
@WebServlet(name = "login", urlPatterns = {"/login"})
public class login extends HttpServlet {
    private ClienteJpaController loginService;
    private EntityManagerFactory emf;

    @Override
    public void init() throws ServletException {
        super.init();
        
        try {
            emf = Persistence.createEntityManagerFactory("com.mycompany_CriptoPractica02_war_1.0-SNAPSHOTPU");
            loginService = new ClienteJpaController(emf);
            System.out.println("✅ Servlet de login inicializado correctamente");
        } catch (Exception e) {
            System.err.println("❌ Error al inicializar servlet: " + e.getMessage());
            throw new ServletException("Error al inicializar conexión a BD", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        response.setContentType("application/json;charset=UTF-8");
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        PrintWriter out = response.getWriter();
        JSONObject jsonResponse = new JSONObject();

        try {
            // Leer el cuerpo de la petición JSON
            StringBuilder sb = new StringBuilder();
            BufferedReader reader = request.getReader();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            
            String requestBodyString = sb.toString().trim();
            System.out.println("📥 Request body recibido: " + requestBodyString);
            
            if (requestBodyString.isEmpty()) {
                throw new Exception("Cuerpo de petición vacío");
            }

            JSONObject requestBody = new JSONObject(requestBodyString);

            String usuario = requestBody.optString("usuario", "").trim();
            String claveEncriptada = requestBody.optString("clave", "").trim();
            
            System.out.println("=== PROCESO DE LOGIN ===");
            System.out.println("👤 Usuario: '" + usuario + "'");
            System.out.println("🔐 Clave encriptada: " + claveEncriptada);
            
            if (usuario.isEmpty() || claveEncriptada.isEmpty()) {
                jsonResponse.put("status", "fail");
                jsonResponse.put("message", "Usuario y contraseña son requeridos");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print(jsonResponse.toString());
                out.flush();
                return;
            }

            // PASO 1: Descifrar la contraseña que viene del cliente (AES)
            String claveDescifrada;
            try {
                claveDescifrada = CryptoUtil.decrypt(claveEncriptada);
                System.out.println("🔓 Clave descifrada: '" + claveDescifrada + "'");
                
                if (claveDescifrada == null || claveDescifrada.trim().isEmpty()) {
                    throw new Exception("Contraseña descifrada está vacía");
                }
                
            } catch (Exception e) {
                System.err.println("❌ Error al descifrar contraseña: " + e.getMessage());
                e.printStackTrace();
                jsonResponse.put("status", "fail");
                jsonResponse.put("message", "Error en el procesamiento de credenciales");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                out.print(jsonResponse.toString());
                out.flush();
                return;
            }

            // PASO 2: Hashear la contraseña descifrada (NUEVO - ESTO FALTABA)
            String claveHasheada;
            try {
                claveHasheada = HashUtil.hashPassword(claveDescifrada);
                System.out.println("🔐 Clave hasheada: " + claveHasheada);
            } catch (Exception e) {
                System.err.println("❌ Error al hashear contraseña: " + e.getMessage());
                e.printStackTrace();
                jsonResponse.put("status", "fail");
                jsonResponse.put("message", "Error en el procesamiento de credenciales");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                out.print(jsonResponse.toString());
                out.flush();
                return;
            }

            // PASO 3: Validar usuario y contraseña hasheada
            System.out.println("🔍 Validando credenciales en BD...");
            Cliente usuarioValido = null;
            
            try {
                // Ahora pasamos la clave hasheada, no la descifrada
                usuarioValido = loginService.validarCliente(usuario, claveHasheada);
                System.out.println("🔍 Resultado validación: " + (usuarioValido != null ? "ENCONTRADO" : "NO ENCONTRADO"));
            } catch (Exception e) {
                System.err.println("❌ Error en validación BD: " + e.getMessage());
                e.printStackTrace();
                jsonResponse.put("status", "error");
                jsonResponse.put("message", "Error al consultar base de datos");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                out.print(jsonResponse.toString());
                out.flush();
                return;
            }

            if (usuarioValido != null) {
                // LOGIN EXITOSO
                System.out.println("✅ Login exitoso para: " + usuarioValido.getNombClie());
                
                request.getSession().setAttribute("usuario", usuarioValido);
                request.getSession().setAttribute("userId", usuarioValido.getNdniClie());
                request.getSession().setAttribute("userName", usuarioValido.getNombClie());
                
                jsonResponse.put("status", "ok");
                jsonResponse.put("redirect", "tabla.html");
                jsonResponse.put("message", "Bienvenido " + usuarioValido.getNombClie());
                
            } else {
                // CREDENCIALES INCORRECTAS
                System.out.println("❌ Credenciales incorrectas para usuario: '" + usuario + "'");
                
                jsonResponse.put("status", "fail");
                jsonResponse.put("message", "Usuario o contraseña incorrectos");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }

        } catch (Exception e) {
            System.err.println("❌ Error general en proceso de login: " + e.getMessage());
            e.printStackTrace();
            
            jsonResponse.put("status", "error");
            jsonResponse.put("message", "Error interno del servidor");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        out.print(jsonResponse.toString());
        out.flush();
        System.out.println("📤 Respuesta enviada: " + jsonResponse.toString());
    }
    
    @Override
    public void destroy() {
        if (emf != null && emf.isOpen()) {
            emf.close();
            System.out.println("🔚 EntityManagerFactory cerrado");
        }
        super.destroy();
    }
}
