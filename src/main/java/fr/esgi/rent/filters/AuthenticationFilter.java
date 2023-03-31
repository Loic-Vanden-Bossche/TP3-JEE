package fr.esgi.rent.filters;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.Base64;
import java.util.List;
import static jakarta.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

@Provider
public class AuthenticationFilter implements ContainerRequestFilter {
    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (requestContext.getUriInfo().getPath().contains("owners")) {
            return;
        }

        List<String> authHeader = requestContext.getHeaders().get(AUTHORIZATION);
        if (authHeader != null && authHeader.size() > 0) {
            String authToken = authHeader.get(0);
            authToken = authToken.replaceFirst("Basic ", "");
            String decodedString = new String(Base64.getDecoder().decode(authToken));
            String[] usernameAndPassword = decodedString.split(":");
            if (usernameAndPassword.length == 2) {
                String username = usernameAndPassword[0];
                String password = usernameAndPassword[1];
                if (username.equals("admin") && password.equals("admin")) {
                    return;
                }
            }
        }

        Response unauthorizedStatus = Response
                .status(Response.Status.UNAUTHORIZED)
                .entity("User cannot access the resource.")
                .type(APPLICATION_JSON)
                .build();

        requestContext.abortWith(unauthorizedStatus);
    }
}
