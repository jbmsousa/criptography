package cv.sousa.server.service;

import cv.sousa.server.model.Message;
import cv.sousa.server.repository.MessageRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@ApplicationScoped
public class MessageService {

    @Inject
    MessageRepository messageRepository;

    @Transactional
    public Message saveMessage(String senderId, String recipientId, String sessionId,
                               String encryptedContent, String signature) {
        Message message = new Message();
        message.senderId = senderId;
        message.recipientId = recipientId;
        message.sessionId = sessionId;
        message.encryptedContent = encryptedContent;
        message.signature = signature;
        message.sentAt = LocalDateTime.now();

        messageRepository.persist(message);
        return message;
    }

    public List<Message> getMessagesBetweenUsers(String user1, String user2) {
        return messageRepository.findBetweenUsers(user1, user2);
    }

    public List<Message> getMessagesBySession(String sessionId) {
        return messageRepository.findBySession(sessionId);
    }

    public List<Message> getUndeliveredMessages(String userId) {
        return messageRepository.findUndeliveredForUser(userId);
    }

    public long getUnreadCount(String userId) {
        return messageRepository.countUnreadForUser(userId);
    }

    @Transactional
    public void markAsDelivered(Long messageId) {
        messageRepository.markAsDelivered(messageId);
    }

    @Transactional
    public void markAsRead(Long messageId) {
        messageRepository.markAsRead(messageId);
    }

    @Transactional
    public void markAllAsRead(String senderId, String recipientId) {
        messageRepository.markAllAsReadBetweenUsers(senderId, recipientId);
    }

    public List<Message> getRecentMessages(String user1, String user2, int limit) {
        return messageRepository.findRecentMessages(user1, user2, limit);
    }
}
