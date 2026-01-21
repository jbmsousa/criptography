package cv.sousa.server.resource;

import cv.sousa.server.model.RevokedKey;
import cv.sousa.server.model.User;
import cv.sousa.server.service.AuthService;
import cv.sousa.server.service.KeyRevocationService;
import cv.sousa.server.service.UserService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.List;
import java.util.Map;

@Path("/api/revocation")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RevocationResource {

    @Inject
    KeyRevocationService revocationService;

    @Inject
    AuthService authService;

    @Inject
    UserService userService;

    @POST
    @Path("/revoke")
    @Transactional
    public Response revoke(@HeaderParam("Authorization") String authHeader, RevocationRequest req) {
        // Extract and validate token
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        // Validate user is revoking their own keys
        return authService.validateSession(token)
            .map(authenticatedUserId -> {
                if (!authenticatedUserId.equals(req.userId)) {
                    return Response.status(403)
                        .entity(new ErrorResponse("Can only revoke your own keys"))
                        .build();
                }

                try {
                    // Get user's current keys
                    User user = userService.findByUserId(req.userId).orElse(null);
                    if (user == null) {
                        return Response.status(404)
                            .entity(new ErrorResponse("User not found"))
                            .build();
                    }

                    // Calculate fingerprint and revoke
                    String ecdhFingerprint = revocationService.calculateFingerprint(user.ecdhPublicKey);
                    String rsaFingerprint = revocationService.calculateFingerprint(user.rsaPublicKey);

                    // Revoke ECDH key
                    if (!revocationService.isKeyRevoked(ecdhFingerprint)) {
                        revocationService.revokeKey(req.userId, ecdhFingerprint, req.reason + " (ECDH)");
                    }

                    // Revoke RSA key
                    if (!revocationService.isKeyRevoked(rsaFingerprint)) {
                        revocationService.revokeKey(req.userId, rsaFingerprint, req.reason + " (RSA)");
                    }

                    // Invalidate all user sessions
                    authService.invalidateAllUserSessions(req.userId);

                    return Response.ok(new SuccessResponse("Keys revoked successfully")).build();
                } catch (Exception e) {
                    return Response.status(500)
                        .entity(new ErrorResponse("Revocation failed: " + e.getMessage()))
                        .build();
                }
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @GET
    @Path("/check/{fingerprint}")
    public Response checkRevocation(@PathParam("fingerprint") String fingerprint) {
        boolean revoked = revocationService.isKeyRevoked(fingerprint);
        return Response.ok(Map.of("revoked", revoked, "fingerprint", fingerprint)).build();
    }

    @GET
    @Path("/check-user/{userId}")
    public Response checkUserRevocation(@PathParam("userId") String userId) {
        return userService.findByUserId(userId)
            .map(user -> {
                try {
                    boolean ecdhRevoked = false;
                    boolean rsaRevoked = false;

                    if (user.ecdhPublicKey != null) {
                        String ecdhFp = revocationService.calculateFingerprint(user.ecdhPublicKey);
                        ecdhRevoked = revocationService.isKeyRevoked(ecdhFp);
                    }

                    if (user.rsaPublicKey != null) {
                        String rsaFp = revocationService.calculateFingerprint(user.rsaPublicKey);
                        rsaRevoked = revocationService.isKeyRevoked(rsaFp);
                    }

                    return Response.ok(Map.of(
                        "userId", userId,
                        "ecdhKeyRevoked", ecdhRevoked,
                        "rsaKeyRevoked", rsaRevoked,
                        "anyKeyRevoked", ecdhRevoked || rsaRevoked
                    )).build();
                } catch (Exception e) {
                    return Response.status(500)
                        .entity(new ErrorResponse("Check failed: " + e.getMessage()))
                        .build();
                }
            })
            .orElse(Response.status(404).entity(new ErrorResponse("User not found")).build());
    }

    @GET
    @Path("/list")
    public Response getRevocationList(@QueryParam("since") String since) {
        List<RevokedKey> revocations;

        if (since != null && !since.isEmpty()) {
            try {
                java.time.LocalDateTime sinceDate = java.time.LocalDateTime.parse(since);
                revocations = revocationService.getRevocationListSince(sinceDate);
            } catch (Exception e) {
                return Response.status(400).entity(new ErrorResponse("Invalid date format")).build();
            }
        } else {
            revocations = revocationService.getRevocationList();
        }

        return Response.ok(revocations.stream().map(RevocationResponse::new).toList()).build();
    }

    @GET
    @Path("/stats")
    public Response getStats() {
        KeyRevocationService.RevocationStats stats = revocationService.getStats();
        return Response.ok(Map.of(
            "totalRevoked", stats.totalRevoked,
            "revokedLast24Hours", stats.revokedLast24Hours,
            "revokedLast7Days", stats.revokedLast7Days
        )).build();
    }

    @POST
    @Path("/refresh-cache")
    public Response refreshCache(@HeaderParam("Authorization") String authHeader) {
        // This would typically require admin privileges
        revocationService.refreshCache();
        return Response.ok(new SuccessResponse("Cache refreshed")).build();
    }

    private String extractToken(String authHeader) {
        if (authHeader == null) return null;
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return authHeader;
    }

    // DTOs
    public static class RevocationRequest {
        public String userId;
        public String reason;
    }

    public static class RevocationResponse {
        public Long id;
        public String userId;
        public String publicKeyFingerprint;
        public String reason;
        public String revokedAt;

        public RevocationResponse(RevokedKey rk) {
            this.id = rk.id;
            this.userId = rk.userId;
            this.publicKeyFingerprint = rk.publicKeyFingerprint;
            this.reason = rk.reason;
            this.revokedAt = rk.revokedAt != null ? rk.revokedAt.toString() : null;
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
