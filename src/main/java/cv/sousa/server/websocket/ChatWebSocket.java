package cv.sousa.server.websocket;

import cv.sousa.server.model.Message;
import cv.sousa.server.service.AuthService;
import cv.sousa.server.service.MessageService;
import cv.sousa.server.service.UserService;
import io.quarkus.arc.Arc;
import io.quarkus.arc.ManagedContext;
import io.quarkus.websockets.next.*;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@WebSocket(path = "/chat")
public class ChatWebSocket {

    @Inject
    AuthService authService;

    @Inject
    MessageService messageService;

    @Inject
    UserService userService;

    // Map of userId -> WebSocket connection
    private static final Map<String, WebSocketConnection> activeConnections = new ConcurrentHashMap<>();

    @OnOpen
    public void onOpen(WebSocketConnection connection) {
        System.out.println("WebSocket connection opened: " + connection.id());
    }

    @OnTextMessage
    public void onMessage(WebSocketConnection connection, String message) {
        try {
            ChatMessage chatMessage = parseMessage(message);

            switch (chatMessage.type) {
                case "auth" -> handleAuth(connection, chatMessage);
                case "message" -> handleChatMessage(connection, chatMessage);
                case "typing" -> handleTyping(connection, chatMessage);
                case "key_exchange" -> handleKeyExchange(connection, chatMessage);
                case "ack" -> handleAcknowledge(connection, chatMessage);
                default -> sendError(connection, "Unknown message type: " + chatMessage.type);
            }
        } catch (Exception e) {
            sendError(connection, "Error processing message: " + e.getMessage());
        }
    }

    @OnClose
    public void onClose(WebSocketConnection connection) {
        // Find and remove user from active connections
        String disconnectedUserId = getUserIdByConnection(connection);
        activeConnections.entrySet().removeIf(entry -> entry.getValue().id().equals(connection.id()));

        // Update database and broadcast offline status
        if (disconnectedUserId != null) {
            ManagedContext requestContext = Arc.container().requestContext();
            requestContext.activate();
            try {
                userService.setUserOnline(disconnectedUserId, false);
            } finally {
                requestContext.deactivate();
            }
            broadcastUserStatus(disconnectedUserId, false);
        }
        System.out.println("WebSocket connection closed: " + connection.id());
    }

    @OnError
    public void onError(WebSocketConnection connection, Throwable error) {
        System.err.println("WebSocket error: " + error.getMessage());
        String disconnectedUserId = getUserIdByConnection(connection);
        activeConnections.entrySet().removeIf(entry -> entry.getValue().id().equals(connection.id()));

        // Update database status on error
        if (disconnectedUserId != null) {
            ManagedContext requestContext = Arc.container().requestContext();
            requestContext.activate();
            try {
                userService.setUserOnline(disconnectedUserId, false);
            } finally {
                requestContext.deactivate();
            }
            broadcastUserStatus(disconnectedUserId, false);
        }
    }

    private void handleAuth(WebSocketConnection connection, ChatMessage message) {
        String token = message.token;
        if (token == null) {
            sendError(connection, "Authentication token required");
            return;
        }

        authService.validateSession(token).ifPresentOrElse(
            userId -> {
                activeConnections.put(userId, connection);

                // Activate request context for database operations
                ManagedContext requestContext = Arc.container().requestContext();
                requestContext.activate();
                try {
                    // Update user online status in database
                    userService.setUserOnline(userId, true);

                    // Send auth success
                    connection.sendTextAndAwait(buildResponse("auth_success", userId, null, null));

                    // Broadcast user online status to all other connected users
                    broadcastUserStatus(userId, true);

                    // Send any undelivered messages
                    messageService.getUndeliveredMessages(userId).forEach(msg -> {
                        connection.sendTextAndAwait(buildMessageResponse(msg));
                        messageService.markAsDelivered(msg.id);
                    });
                } finally {
                    requestContext.deactivate();
                }
            },
            () -> sendError(connection, "Invalid authentication token")
        );
    }

    private void handleChatMessage(WebSocketConnection connection, ChatMessage message) {
        String senderId = getUserIdByConnection(connection);
        if (senderId == null) {
            sendError(connection, "Not authenticated");
            return;
        }

        System.out.println("Storing message - encryptedContent: " +
            (message.encryptedContent != null ? message.encryptedContent.substring(0, Math.min(100, message.encryptedContent.length())) : "null"));

        // Activate request context for database operations
        ManagedContext requestContext = Arc.container().requestContext();
        requestContext.activate();
        try {
            // Store the message
            Message storedMessage = messageService.saveMessage(
                senderId,
                message.recipientId,
                message.sessionId,
                message.encryptedContent,
                message.signature
            );

            // Try to deliver to recipient
            WebSocketConnection recipientConnection = activeConnections.get(message.recipientId);
            if (recipientConnection != null) {
                recipientConnection.sendTextAndAwait(buildMessageResponse(storedMessage));
                messageService.markAsDelivered(storedMessage.id);

                // Send delivery confirmation to sender
                connection.sendTextAndAwait(buildResponse("delivered", message.recipientId, storedMessage.id.toString(), null));
            } else {
                // Message stored but not delivered (recipient offline)
                connection.sendTextAndAwait(buildResponse("stored", message.recipientId, storedMessage.id.toString(), null));
            }
        } finally {
            requestContext.deactivate();
        }
    }

    private void handleTyping(WebSocketConnection connection, ChatMessage message) {
        String senderId = getUserIdByConnection(connection);
        if (senderId == null) return;

        WebSocketConnection recipientConnection = activeConnections.get(message.recipientId);
        if (recipientConnection != null) {
            recipientConnection.sendTextAndAwait(
                String.format("{\"type\":\"typing\",\"senderId\":\"%s\",\"isTyping\":%s}",
                    senderId, message.isTyping)
            );
        }
    }

    private void handleKeyExchange(WebSocketConnection connection, ChatMessage message) {
        String senderId = getUserIdByConnection(connection);
        if (senderId == null) {
            sendError(connection, "Not authenticated");
            return;
        }

        WebSocketConnection recipientConnection = activeConnections.get(message.recipientId);
        if (recipientConnection != null) {
            recipientConnection.sendTextAndAwait(
                String.format("{\"type\":\"key_exchange\",\"senderId\":\"%s\",\"sessionId\":\"%s\",\"publicKey\":\"%s\",\"salt\":\"%s\"}",
                    senderId, message.sessionId, message.publicKey, message.salt != null ? message.salt : "")
            );
            connection.sendTextAndAwait(buildResponse("key_exchange_sent", message.recipientId, message.sessionId, null));
        } else {
            sendError(connection, "Recipient is not online");
        }
    }

    private void handleAcknowledge(WebSocketConnection connection, ChatMessage message) {
        if (message.messageId != null) {
            // Activate request context for database operations
            ManagedContext requestContext = Arc.container().requestContext();
            requestContext.activate();
            try {
                messageService.markAsRead(Long.parseLong(message.messageId));

                // Notify sender that message was read
                String senderId = message.senderId;
                WebSocketConnection senderConnection = activeConnections.get(senderId);
                if (senderConnection != null) {
                    senderConnection.sendTextAndAwait(
                        String.format("{\"type\":\"read\",\"messageId\":\"%s\"}", message.messageId)
                    );
                }
            } finally {
                requestContext.deactivate();
            }
        }
    }

    private String getUserIdByConnection(WebSocketConnection connection) {
        return activeConnections.entrySet().stream()
            .filter(entry -> entry.getValue().id().equals(connection.id()))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    private void sendError(WebSocketConnection connection, String errorMessage) {
        connection.sendTextAndAwait(String.format("{\"type\":\"error\",\"message\":\"%s\"}", errorMessage));
    }

    private String buildResponse(String type, String userId, String messageId, String data) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"type\":\"").append(type).append("\"");
        if (userId != null) sb.append(",\"userId\":\"").append(userId).append("\"");
        if (messageId != null) sb.append(",\"messageId\":\"").append(messageId).append("\"");
        if (data != null) sb.append(",\"data\":\"").append(data).append("\"");
        sb.append("}");
        return sb.toString();
    }

    private String buildMessageResponse(Message msg) {
        // Escape encryptedContent since it contains JSON with quotes
        String escapedContent = msg.encryptedContent != null
            ? msg.encryptedContent.replace("\\", "\\\\").replace("\"", "\\\"")
            : "";
        String escapedSignature = msg.signature != null
            ? msg.signature.replace("\\", "\\\\").replace("\"", "\\\"")
            : "";
        return String.format(
            "{\"type\":\"message\",\"id\":\"%d\",\"senderId\":\"%s\",\"recipientId\":\"%s\",\"sessionId\":\"%s\",\"encryptedContent\":\"%s\",\"signature\":\"%s\",\"timestamp\":\"%s\"}",
            msg.id, msg.senderId, msg.recipientId,
            msg.sessionId != null ? msg.sessionId : "",
            escapedContent, escapedSignature,
            msg.sentAt.toString()
        );
    }

    private ChatMessage parseMessage(String json) {
        // Simple JSON parsing (in production, use Jackson)
        System.out.println("Parsing message: " + json.substring(0, Math.min(200, json.length())));
        ChatMessage msg = new ChatMessage();
        msg.type = extractJsonValue(json, "type");
        msg.token = extractJsonValue(json, "token");
        msg.recipientId = extractJsonValue(json, "recipientId");
        msg.senderId = extractJsonValue(json, "senderId");
        msg.sessionId = extractJsonValue(json, "sessionId");
        msg.messageId = extractJsonValue(json, "messageId");
        msg.encryptedContent = extractJsonValue(json, "encryptedContent");
        msg.signature = extractJsonValue(json, "signature");
        msg.publicKey = extractJsonValue(json, "publicKey");
        msg.salt = extractJsonValue(json, "salt");
        msg.isTyping = "true".equals(extractJsonValue(json, "isTyping"));
        System.out.println("Extracted encryptedContent: " +
            (msg.encryptedContent != null ? msg.encryptedContent.substring(0, Math.min(100, msg.encryptedContent.length())) : "null"));
        return msg;
    }

    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) return null;

        int valueStart = keyIndex + searchKey.length();
        while (valueStart < json.length() && json.charAt(valueStart) == ' ') valueStart++;

        if (valueStart >= json.length()) return null;

        if (json.charAt(valueStart) == '"') {
            // Find closing quote, handling escaped quotes
            int valueEnd = valueStart + 1;
            while (valueEnd < json.length()) {
                char c = json.charAt(valueEnd);
                if (c == '"' && json.charAt(valueEnd - 1) != '\\') {
                    break;
                }
                valueEnd++;
            }
            if (valueEnd >= json.length()) return null;
            // Unescape the value
            String value = json.substring(valueStart + 1, valueEnd);
            return value.replace("\\\"", "\"").replace("\\\\", "\\");
        } else {
            int valueEnd = valueStart;
            while (valueEnd < json.length() && json.charAt(valueEnd) != ',' && json.charAt(valueEnd) != '}') {
                valueEnd++;
            }
            return json.substring(valueStart, valueEnd).trim();
        }
    }

    public static boolean isUserOnline(String userId) {
        return activeConnections.containsKey(userId);
    }

    public static void broadcastToUser(String userId, String message) {
        WebSocketConnection connection = activeConnections.get(userId);
        if (connection != null) {
            connection.sendTextAndAwait(message);
        }
    }

    private void broadcastUserStatus(String userId, boolean isOnline) {
        String statusMessage = String.format(
            "{\"type\":\"user_status\",\"userId\":\"%s\",\"isOnline\":%s}",
            userId, isOnline
        );
        // Broadcast to all other connected users
        activeConnections.forEach((connectedUserId, conn) -> {
            if (!connectedUserId.equals(userId)) {
                try {
                    conn.sendTextAndAwait(statusMessage);
                } catch (Exception e) {
                    System.err.println("Failed to send status to " + connectedUserId + ": " + e.getMessage());
                }
            }
        });
    }

    // Inner class for message parsing
    private static class ChatMessage {
        String type;
        String token;
        String recipientId;
        String senderId;
        String sessionId;
        String messageId;
        String encryptedContent;
        String signature;
        String publicKey;
        String salt;
        boolean isTyping;
    }
}
