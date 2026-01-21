package cv.sousa.client.model;

import java.util.Base64;

/**
 * Representa uma mensagem segura com cifra, assinatura e metadados
 */
public class SecureMessage {
  private String senderId;
  private String recipientId;
  private byte[] encryptedContent;
  private byte[] signature;
  private byte[] encryptedSessionKey; // Para primeira mensagem
  private long timestamp;

  public SecureMessage() {
    this.timestamp = System.currentTimeMillis();
  }

  public SecureMessage(String senderId, String recipientId,
      byte[] encryptedContent, byte[] signature) {
    this();
    this.senderId = senderId;
    this.recipientId = recipientId;
    this.encryptedContent = encryptedContent;
    this.signature = signature;
  }

  // Getters e Setters
  public String getSenderId() { return senderId; }
  public void setSenderId(String senderId) { this.senderId = senderId; }

  public String getRecipientId() { return recipientId; }
  public void setRecipientId(String recipientId) {
    this.recipientId = recipientId;
  }

  public byte[] getEncryptedContent() { return encryptedContent; }
  public void setEncryptedContent(byte[] encryptedContent) {
    this.encryptedContent = encryptedContent;
  }

  public byte[] getSignature() { return signature; }
  public void setSignature(byte[] signature) {
    this.signature = signature;
  }

  public byte[] getEncryptedSessionKey() { return encryptedSessionKey; }
  public void setEncryptedSessionKey(byte[] encryptedSessionKey) {
    this.encryptedSessionKey = encryptedSessionKey;
  }

  public long getTimestamp() { return timestamp; }
  public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

  /**
   * Serializa a mensagem para JSON
   */
  public String toJson() {
    return String.format("""
            {
                "senderId": "%s",
                "recipientId": "%s",
                "encryptedContent": "%s",
                "signature": "%s",
                "encryptedSessionKey": %s,
                "timestamp": %d
            }
            """,
        senderId,
        recipientId,
        Base64.getEncoder().encodeToString(encryptedContent),
        Base64.getEncoder().encodeToString(signature),
        encryptedSessionKey != null ?
            "\"" + Base64.getEncoder().encodeToString(encryptedSessionKey) + "\""
            : "null",
        timestamp
    );
  }

  /**
   * Verifica se é a primeira mensagem da sessão
   */
  public boolean isSessionInitiation() {
    return encryptedSessionKey != null;
  }

  @Override
  public String toString() {
    return String.format("SecureMessage[%s -> %s, encrypted=%d bytes, signed=%d bytes]",
        senderId, recipientId,
        encryptedContent != null ? encryptedContent.length : 0,
        signature != null ? signature.length : 0);
  }
}
