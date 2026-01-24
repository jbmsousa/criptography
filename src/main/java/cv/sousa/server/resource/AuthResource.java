package cv.sousa.server.resource;

import cv.sousa.server.model.User;
import cv.sousa.server.service.AuthService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@Path("/api/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Authentication", description = "Autenticacao e gestao de sessoes")
public class AuthResource {

    @Inject
    AuthService authService;

    @POST
    @Path("/login")
    @Operation(summary = "Autenticar utilizador",
               description = "Autentica um utilizador com NIF e password, retorna token de sessao")
    @APIResponse(responseCode = "200", description = "Autenticacao bem sucedida",
                 content = @Content(schema = @Schema(implementation = LoginResponse.class)))
    @APIResponse(responseCode = "401", description = "Credenciais invalidas")
    public Response login(LoginRequest req) {
        if (req.userId == null || req.password == null) {
            return Response.status(400)
                .entity(new ErrorResponse("User ID and password are required"))
                .build();
        }

        return authService.login(req.userId, req.password)
            .map(token -> Response.ok(new LoginResponse(token, req.userId)).build())
            .orElse(Response.status(401)
                .entity(new ErrorResponse("Invalid credentials"))
                .build());
    }

    @POST
    @Path("/logout")
    @Operation(summary = "Terminar sessao",
               description = "Invalida o token de sessao atual e marca utilizador como offline")
    @APIResponse(responseCode = "200", description = "Sessao terminada com sucesso")
    public Response logout(@HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(400)
                .entity(new ErrorResponse("Authorization token required"))
                .build();
        }

        authService.logout(token);
        return Response.ok(new SuccessResponse("Logged out successfully")).build();
    }

    @GET
    @Path("/validate")
    @Operation(summary = "Validar sessao",
               description = "Verifica se o token de sessao e valido e retorna informacao do utilizador")
    @APIResponse(responseCode = "200", description = "Sessao valida",
                 content = @Content(schema = @Schema(implementation = UserInfoResponse.class)))
    @APIResponse(responseCode = "401", description = "Sessao invalida ou expirada")
    public Response validateSession(@HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(400)
                .entity(new ErrorResponse("Authorization token required"))
                .build();
        }

        return authService.getAuthenticatedUser(token)
            .map(user -> Response.ok(new UserInfoResponse(user)).build())
            .orElse(Response.status(401)
                .entity(new ErrorResponse("Invalid or expired session"))
                .build());
    }

    @POST
    @Path("/challenge")
    @Operation(summary = "Gerar desafio criptografico",
               description = "Gera um desafio aleatorio para verificacao de posse de chave privada RSA")
    @APIResponse(responseCode = "200", description = "Desafio gerado",
                 content = @Content(schema = @Schema(implementation = ChallengeResponse.class)))
    public Response generateChallenge(ChallengeRequest req) {
        if (req.userId == null) {
            return Response.status(400)
                .entity(new ErrorResponse("User ID is required"))
                .build();
        }

        String challenge = authService.generateChallenge(req.userId);
        return Response.ok(new ChallengeResponse(challenge)).build();
    }

    @POST
    @Path("/verify-key")
    @Operation(summary = "Verificar posse de chave",
               description = "Verifica que o utilizador possui a chave privada RSA correspondente a chave publica registada")
    @APIResponse(responseCode = "200", description = "Posse de chave verificada")
    @APIResponse(responseCode = "401", description = "Verificacao falhou")
    public Response verifyKeyOwnership(VerifyKeyRequest req) {
        if (req.userId == null || req.signedChallenge == null) {
            return Response.status(400)
                .entity(new ErrorResponse("User ID and signed challenge are required"))
                .build();
        }

        boolean valid = authService.verifyChallengeResponse(req.userId, req.signedChallenge);
        if (valid) {
            return Response.ok(new SuccessResponse("Key ownership verified")).build();
        } else {
            return Response.status(401)
                .entity(new ErrorResponse("Key verification failed"))
                .build();
        }
    }

    private String extractToken(String authHeader) {
        if (authHeader == null) return null;
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return authHeader;
    }

    // DTOs
    public static class LoginRequest {
        public String userId;
        public String password;
    }

    public static class LoginResponse {
        public String token;
        public String userId;
        public LoginResponse(String token, String userId) {
            this.token = token;
            this.userId = userId;
        }
    }

    public static class ChallengeRequest {
        public String userId;
    }

    public static class ChallengeResponse {
        public String challenge;
        public ChallengeResponse(String challenge) { this.challenge = challenge; }
    }

    public static class VerifyKeyRequest {
        public String userId;
        public String signedChallenge;
    }

    public static class UserInfoResponse {
        public String nif;
        public String nome;
        public String email;
        public String userId; // Alias for backward compatibility
        public String keyFingerprint;
        public boolean isOnline;

        public UserInfoResponse(User user) {
            this.nif = user.nif;
            this.nome = user.nome;
            this.email = user.email;
            this.userId = user.nif; // Backward compatibility
            this.keyFingerprint = user.keyFingerprint;
            this.isOnline = user.isOnline;
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
