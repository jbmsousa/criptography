package cv.sousa.server.resource;

import cv.sousa.server.model.User;
import cv.sousa.server.service.UserService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.List;

@Path("/api/keys")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class KeyRegistryResource {

    @Inject
    UserService userService;

    @POST
    @Path("/register")
    @Transactional
    public Response register(RegistrationRequest req) {
        if (req.userId == null || req.userId.isBlank()) {
            return Response.status(400).entity(new ErrorResponse("User ID is required")).build();
        }
        if (req.password == null || req.password.length() < 8) {
            return Response.status(400).entity(new ErrorResponse("Password must be at least 8 characters")).build();
        }
        if (req.ecdhPublicKey == null || req.rsaPublicKey == null) {
            return Response.status(400).entity(new ErrorResponse("Both ECDH and RSA public keys are required")).build();
        }

        if (userService.existsByUserId(req.userId)) {
            return Response.status(409).entity(new ErrorResponse("User already exists")).build();
        }

        try {
            User user = userService.registerUser(req.userId, req.password, req.ecdhPublicKey, req.rsaPublicKey);
            return Response.status(201).entity(new UserResponse(user)).build();
        } catch (Exception e) {
            return Response.status(500).entity(new ErrorResponse("Registration failed: " + e.getMessage())).build();
        }
    }

    @GET
    @Path("/{userId}")
    public Response getUser(@PathParam("userId") String userId) {
        return userService.findByUserId(userId)
            .map(user -> Response.ok(new UserResponse(user)).build())
            .orElse(Response.status(404).entity(new ErrorResponse("User not found")).build());
    }

    @GET
    @Path("/users")
    public List<UserResponse> listUsers() {
        return userService.getAllUsers().stream()
            .map(UserResponse::new)
            .toList();
    }

    @GET
    @Path("/users/online")
    public List<UserResponse> listOnlineUsers() {
        return userService.getOnlineUsers().stream()
            .map(UserResponse::new)
            .toList();
    }

    @PUT
    @Path("/{userId}/keys")
    @Transactional
    public Response updateKeys(@PathParam("userId") String userId,
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
        public String userId;
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
        public String userId;
        public String ecdhPublicKey;
        public String rsaPublicKey;
        public String keyFingerprint;
        public boolean isOnline;
        public String registeredAt;

        public UserResponse(User user) {
            this.id = user.id;
            this.userId = user.userId;
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
