package cv.sousa.server.resource;

import cv.sousa.server.model.User;
import cv.sousa.server.service.UserService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import java.util.List;

@Path("/api/keys")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Key Registry", description = "Autoridade de Registo - Gestao de chaves publicas e utilizadores")
public class KeyRegistryResource {

    @Inject
    UserService userService;

    @POST
    @Path("/register")
    @Transactional
    @Operation(summary = "Registar novo utilizador",
               description = "Regista um novo utilizador com NIF, password e chaves publicas ECDH e RSA")
    @APIResponse(responseCode = "201", description = "Utilizador registado com sucesso",
                 content = @Content(schema = @Schema(implementation = UserResponse.class)))
    @APIResponse(responseCode = "400", description = "Dados invalidos")
    @APIResponse(responseCode = "409", description = "Utilizador ja existe")
    public Response register(RegistrationRequest req) {
        if (req.nif == null || req.nif.isBlank()) {
            return Response.status(400).entity(new ErrorResponse("NIF is required")).build();
        }
        if (req.nome == null || req.nome.trim().length() < 3) {
            return Response.status(400).entity(new ErrorResponse("Nome must be at least 3 characters")).build();
        }
        if (req.email == null || req.email.isBlank()) {
            return Response.status(400).entity(new ErrorResponse("Email is required")).build();
        }
        if (req.password == null || req.password.length() < 8) {
            return Response.status(400).entity(new ErrorResponse("Password must be at least 8 characters")).build();
        }
        if (req.ecdhPublicKey == null || req.rsaPublicKey == null) {
            return Response.status(400).entity(new ErrorResponse("Both ECDH and RSA public keys are required")).build();
        }

        try {
            User user = userService.registerUser(req.nif, req.nome, req.email, req.password, req.ecdhPublicKey, req.rsaPublicKey);
            return Response.status(201).entity(new UserResponse(user)).build();
        } catch (IllegalArgumentException e) {
            return Response.status(400).entity(new ErrorResponse(e.getMessage())).build();
        } catch (Exception e) {
            return Response.status(500).entity(new ErrorResponse("Registration failed: " + e.getMessage())).build();
        }
    }

    @GET
    @Path("/{userId}")
    @Operation(summary = "Obter chave publica por NIF",
               description = "Retorna as chaves publicas ECDH e RSA de um utilizador especifico")
    @APIResponse(responseCode = "200", description = "Utilizador encontrado",
                 content = @Content(schema = @Schema(implementation = UserResponse.class)))
    @APIResponse(responseCode = "404", description = "Utilizador nao encontrado")
    public Response getUser(
            @Parameter(description = "NIF do utilizador", required = true)
            @PathParam("userId") String userId) {
        return userService.findByUserId(userId)
            .map(user -> Response.ok(new UserResponse(user)).build())
            .orElse(Response.status(404).entity(new ErrorResponse("User not found")).build());
    }

    @GET
    @Path("/users")
    @Operation(summary = "Listar todos os utilizadores",
               description = "Retorna a lista de todos os utilizadores registados")
    public List<UserResponse> listUsers() {
        return userService.getAllUsers().stream()
            .map(UserResponse::new)
            .toList();
    }

    @GET
    @Path("/users/online")
    @Operation(summary = "Listar utilizadores online",
               description = "Retorna a lista de utilizadores atualmente online")
    public List<UserResponse> listOnlineUsers() {
        return userService.getOnlineUsers().stream()
            .map(UserResponse::new)
            .toList();
    }

    @PUT
    @Path("/{userId}/keys")
    @Transactional
    @Operation(summary = "Atualizar chaves publicas",
               description = "Atualiza as chaves publicas ECDH e RSA de um utilizador (requer autenticacao)")
    @APIResponse(responseCode = "200", description = "Chaves atualizadas com sucesso")
    @APIResponse(responseCode = "401", description = "Autorizacao necessaria")
    @APIResponse(responseCode = "404", description = "Utilizador nao encontrado")
    public Response updateKeys(
            @Parameter(description = "NIF do utilizador", required = true)
            @PathParam("userId") String userId,
            @HeaderParam("Authorization") String authToken,
            KeyUpdateRequest req) {
        // Basic auth validation - should verify token
        if (authToken == null || authToken.isBlank()) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        if (!userService.existsByUserId(userId)) {
            return Response.status(404).entity(new ErrorResponse("User not found")).build();
        }

        userService.updateKeys(userId, req.ecdhPublicKey, req.rsaPublicKey);
        return Response.ok(new SuccessResponse("Keys updated successfully")).build();
    }

    // Request/Response DTOs
    public static class RegistrationRequest {
        public String nif;
        public String nome;
        public String email;
        public String password;
        public String ecdhPublicKey;
        public String rsaPublicKey;
    }

    public static class KeyUpdateRequest {
        public String ecdhPublicKey;
        public String rsaPublicKey;
    }

    public static class UserResponse {
        public Long id;
        public String nif;
        public String nome;
        public String email;
        public String userId; // Alias for nif (backward compatibility)
        public String ecdhPublicKey;
        public String rsaPublicKey;
        public String keyFingerprint;
        public boolean isOnline;
        public String registeredAt;

        public UserResponse(User user) {
            this.id = user.id;
            this.nif = user.nif;
            this.nome = user.nome;
            this.email = user.email;
            this.userId = user.nif; // Backward compatibility
            this.ecdhPublicKey = user.ecdhPublicKey;
            this.rsaPublicKey = user.rsaPublicKey;
            this.keyFingerprint = user.keyFingerprint;
            this.isOnline = user.isOnline;
            this.registeredAt = user.registeredAt != null ? user.registeredAt.toString() : null;
        }
    }

    public static class ErrorResponse {
        public String error;
        public ErrorResponse(String error) { this.error = error; }
    }

    public static class SuccessResponse {
        public String message;
        public SuccessResponse(String message) { this.message = message; }
    }
}
