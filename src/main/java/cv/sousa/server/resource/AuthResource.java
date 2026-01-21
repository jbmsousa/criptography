package cv.sousa.server.resource;

import cv.sousa.server.model.User;
import cv.sousa.server.service.AuthService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

@Path("/api/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    AuthService authService;

    @POST
    @Path("/login")
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
        public String userId;
        public String keyFingerprint;
        public boolean isOnline;

        public UserInfoResponse(User user) {
            this.userId = user.userId;
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
