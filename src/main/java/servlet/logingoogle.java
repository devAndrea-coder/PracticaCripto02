package servlet;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author ANDREA
 */
@WebServlet(name = "logingoogle", urlPatterns = {"/logingoogle"})
public class logingoogle extends HttpServlet {
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {

        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        //VA A RESPONDER EN FOMATO JSON
        response.setContentType("application/json;charset=UTF-8");
        PrintWriter out = response.getWriter();

        // Leer JSON con id_token
        StringBuilder sb = new StringBuilder();
        String line;
        try (BufferedReader reader = request.getReader()) {
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        }
        String jsonString = sb.toString();

        // Declara una variable para almacenar el ID token de Google.
        String idTokenString = "";
        try {
            JsonObject json = new Gson().fromJson(jsonString, JsonObject.class);
            idTokenString = json.get("id_token").getAsString();
        } catch (Exception e) {
            out.println("{\"resultado\":\"error\"}");
            return;
        }

        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList("683576227359-a17m87huqbg468fu1tlknkcnru125fl6.apps.googleusercontent.com"))
                    .build();

            // Verifica el ID token recibido.
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken != null) {
                // Obtiene la carga útil (información del usuario) del token.
                GoogleIdToken.Payload payload = idToken.getPayload();

                String email = payload.getEmail();
                // Opcional: validar que el email exista en tu BD o registrarlo

                // Crear JWT propio para tu app
                String token = util.JwtUtil.generarToken(email);

                // Crear sesión y devolver JSON con token
                HttpSession sesion = request.getSession();
                sesion.setAttribute("usuario", email);

                out.println("{\"resultado\":\"ok\",\"token\":\"" + token + "\"}");

            } else {
                out.println("{\"resultado\":\"error\"}");
            }
        } catch (Exception e) {
            e.printStackTrace();
            out.println("{\"resultado\":\"error\"}");
        }
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>
}
