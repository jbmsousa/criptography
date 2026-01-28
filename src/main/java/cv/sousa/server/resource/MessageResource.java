package cv.sousa.server.resource;

import cv.sousa.server.model.Message;
import cv.sousa.server.service.AuthService;
import cv.sousa.server.service.MessageService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.List;

@Path("/api/messages")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class MessageResource {

    @Inject
    MessageService messageService;

    @Inject
    AuthService authService;

    @GET
    @Path("/history/{otherUserId}")
    public Response getMessageHistory(@PathParam("otherUserId") String otherUserId,
                                      @HeaderParam("Authorization") String authHeader,
                                      @QueryParam("limit") @DefaultValue("50") int limit) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(currentUserId -> {
                List<MessageResponse> messages = messageService.getRecentMessages(currentUserId, otherUserId, limit)
                    .stream()
                    .map(MessageResponse::new)
                    .toList();
                return Response.ok(messages).build();
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @GET
    @Path("/undelivered")
    public Response getUndeliveredMessages(@HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(userId -> {
                List<MessageResponse> messages = messageService.getUndeliveredMessages(userId)
                    .stream()
                    .map(MessageResponse::new)
                    .toList();
                return Response.ok(messages).build();
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @GET
    @Path("/unread-count")
    public Response getUnreadCount(@HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(userId -> Response.ok(new UnreadCountResponse(messageService.getUnreadCount(userId))).build())
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @POST
    @Path("/mark-read/{senderId}")
    @Transactional
    public Response markMessagesAsRead(@PathParam("senderId") String senderId,
                                       @HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(recipientId -> {
                messageService.markAllAsRead(senderId, recipientId);
                return Response.ok(new SuccessResponse("Messages marked as read")).build();
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @DELETE
    @Path("/clear-all")
    @Transactional
    public Response clearAllMessages(@HeaderParam("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(userId -> {
                messageService.deleteAllMessages();
                return Response.ok(new SuccessResponse("All messages cleared")).build();
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    @POST
    @Transactional
    public Response storeMessage(@HeaderParam("Authorization") String authHeader, StoreMessageRequest req) {
        String token = extractToken(authHeader);
        if (token == null) {
            return Response.status(401).entity(new ErrorResponse("Authorization required")).build();
        }

        return authService.validateSession(token)
            .map(senderId -> {
                Message message = messageService.saveMessage(
                    senderId,
                    req.recipientId,
                    req.sessionId,
                    req.encryptedContent,
                    req.signature
                );
                return Response.status(201).entity(new MessageResponse(message)).build();
            })
            .orElse(Response.status(401).entity(new ErrorResponse("Invalid session")).build());
    }

    private String extractToken(String authHeader) {
        if (authHeader == null) return null;
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return authHeader;
    }

    // DTOs
    public static class StoreMessageRequest {
        public String recipientId;
        public String sessionId;
        public String encryptedContent;
        public String signature;
    }

    public static class MessageResponse {
        public Long id;
        public String senderId;
        public String recipientId;
        public String sessionId;
        public String encryptedContent;
        public String senderEncryptedContent;
        public String signature;
        public String sentAt;
        public boolean delivered;
        public boolean read;

        public MessageResponse(Message message) {
            this.id = message.id;
            this.senderId = message.senderId;
            this.recipientId = message.recipientId;
            this.sessionId = message.sessionId;
            this.encryptedContent = message.encryptedContent;
            this.senderEncryptedContent = message.senderEncryptedContent;
            this.signature = message.signature;
            this.sentAt = message.sentAt != null ? message.sentAt.toString() : null;
            this.delivered = message.delivered;
            this.read = message.read;
        }
    }

    public static class UnreadCountResponse {
        public long count;
        public UnreadCountResponse(long count) { this.count = count; }
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
