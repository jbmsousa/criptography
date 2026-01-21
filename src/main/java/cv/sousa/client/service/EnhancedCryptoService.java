package cv.sousa.client.service;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.time.Instant;
import java.nio.ByteBuffer;

/**
 * Serviço criptográfico melhorado com:
 * - Perfect Forward Secrecy usando ECDHE
 * - Proteção contra replay attacks
 * - Rotação de chaves de sessão
 * - Timestamps e nonces
 */
public class EnhancedCryptoService {

  private static final String ECDH_CURVE = "secp256r1"; // P-256
  private static final int SESSION_KEY_LIFETIME_MS = 300000; // 5 minutos
  private static final int NONCE_SIZE = 16;
  private static final int REPLAY_WINDOW_MS = 60000; // 1 minuto

  // Cache de nonces para proteção contra replay
  private final Set<String> usedNonces = Collections.synchronizedSet(
      new HashSet<>());
  private final Map<String, Long> nonceTimestamps = Collections.synchronizedMap(
      new HashMap<>());

  // Cache de chaves de sessão com timestamp
  private final Map<String, SessionKeyInfo> sessionKeys =
      Collections.synchronizedMap(new HashMap<>());

  /**
   * Gera par de chaves ECDH para Perfect Forward Secrecy
   */
  public KeyPair generateECDHKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec ecSpec = new ECGenParameterSpec(ECDH_CURVE);
    keyGen.initialize(ecSpec, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  /**
   * Gera par de chaves RSA para assinaturas
   */
  public KeyPair generateRSAKeyPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048, new SecureRandom());
    return keyGen.generateKeyPair();
  }

  /**
   * Deriva chave de sessão usando ECDH
   * Implementa Perfect Forward Secrecy
   */
  public SecretKey deriveSessionKey(PrivateKey myPrivateKey,
      PublicKey otherPublicKey,
      byte[] salt) throws Exception {
    // Acordo ECDH
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
    keyAgreement.init(myPrivateKey);
    keyAgreement.doPhase(otherPublicKey, true);
    byte[] sharedSecret = keyAgreement.generateSecret();

    // KDF usando HKDF-SHA256
    return deriveKeyWithHKDF(sharedSecret, salt, "session-key".getBytes());
  }

  /**
   * HKDF (HMAC-based Key Derivation Function)
   */
  private SecretKey deriveKeyWithHKDF(byte[] inputKey, byte[] salt,
      byte[] info) throws Exception {
    // Extract
    Mac hmac = Mac.getInstance("HmacSHA256");
    hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
    byte[] prk = hmac.doFinal(inputKey);

    // Expand
    hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
    hmac.update(info);
    hmac.update((byte) 1);
    byte[] okm = hmac.doFinal();

    // Retorna 256 bits para AES-256
    return new SecretKeySpec(Arrays.copyOf(okm, 32), "AES");
  }

  /**
   * Cifra mensagem com AES-GCM + proteção contra replay
   */
  public EncryptedMessage encryptMessageSecure(String message,
      SecretKey sessionKey,
      String sessionId)
      throws Exception {
    // Gerar nonce único
    byte[] nonce = generateNonce();
    long timestamp = Instant.now().toEpochMilli();

    // Preparar dados adicionais autenticados (AAD)
    byte[] aad = buildAAD(sessionId, timestamp, nonce);

    // Cifrar com AES-GCM
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    byte[] iv = new byte[12];
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);

    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, sessionKey, spec);
    cipher.updateAAD(aad);

    byte[] ciphertext = cipher.doFinal(message.getBytes());

    return new EncryptedMessage(iv, ciphertext, nonce, timestamp, sessionId);
  }

  /**
   * Decifra mensagem com verificação anti-replay
   */
  public String decryptMessageSecure(EncryptedMessage encMsg,
      SecretKey sessionKey)
      throws Exception {
    // Verificar timestamp (proteção contra replay tardio)
    long currentTime = Instant.now().toEpochMilli();
    if (currentTime - encMsg.timestamp > REPLAY_WINDOW_MS) {
      throw new SecurityException("Message expired - possible replay attack");
    }

    // Verificar nonce (proteção contra replay)
    String nonceStr = Base64.getEncoder().encodeToString(encMsg.nonce);
    if (usedNonces.contains(nonceStr)) {
      throw new SecurityException("Nonce reused - replay attack detected!");
    }

    // Reconstruir AAD
    byte[] aad = buildAAD(encMsg.sessionId, encMsg.timestamp, encMsg.nonce);

    // Decifrar
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec = new GCMParameterSpec(128, encMsg.iv);
    cipher.init(Cipher.DECRYPT_MODE, sessionKey, spec);
    cipher.updateAAD(aad);

    byte[] plaintext = cipher.doFinal(encMsg.ciphertext);

    // Registar nonce como usado
    usedNonces.add(nonceStr);
    nonceTimestamps.put(nonceStr, currentTime);

    // Limpar nonces antigos
    cleanupOldNonces();

    return new String(plaintext);
  }

  /**
   * Assina mensagem com timestamp
   */
  public byte[] signMessage(byte[] message, PrivateKey privateKey,
      long timestamp) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);

    // Incluir timestamp na assinatura
    ByteBuffer buffer = ByteBuffer.allocate(message.length + 8);
    buffer.putLong(timestamp);
    buffer.put(message);

    signature.update(buffer.array());
    return signature.sign();
  }

  /**
   * Verifica assinatura com timestamp
   */
  public boolean verifySignature(byte[] message, byte[] signatureBytes,
      PublicKey publicKey, long timestamp)
      throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initVerify(publicKey);

    // Reconstruir dados com timestamp
    ByteBuffer buffer = ByteBuffer.allocate(message.length + 8);
    buffer.putLong(timestamp);
    buffer.put(message);

    signature.update(buffer.array());
    return signature.verify(signatureBytes);
  }

  /**
   * Gerenciar chaves de sessão com rotação automática
   */
  public SecretKey getOrRotateSessionKey(String sessionId,
      PrivateKey myECDHKey,
      PublicKey otherECDHKey)
      throws Exception {
    SessionKeyInfo keyInfo = sessionKeys.get(sessionId);
    long currentTime = Instant.now().toEpochMilli();

    // Verificar se precisa rotacionar
    if (keyInfo == null ||
        currentTime - keyInfo.createdAt > SESSION_KEY_LIFETIME_MS) {

      System.out.println("🔄 Rotacionando chave de sessão...");

      // Gerar novo salt
      byte[] salt = new byte[32];
      new SecureRandom().nextBytes(salt);

      // Derivar nova chave
      SecretKey newKey = deriveSessionKey(myECDHKey, otherECDHKey, salt);

      keyInfo = new SessionKeyInfo(newKey, currentTime, salt);
      sessionKeys.put(sessionId, keyInfo);
    }

    return keyInfo.key;
  }

  /**
   * Gera nonce criptograficamente seguro
   */
  private byte[] generateNonce() {
    byte[] nonce = new byte[NONCE_SIZE];
    new SecureRandom().nextBytes(nonce);
    return nonce;
  }

  /**
   * Constrói dados adicionais autenticados (AAD)
   */
  private byte[] buildAAD(String sessionId, long timestamp, byte[] nonce) {
    ByteBuffer buffer = ByteBuffer.allocate(
        sessionId.length() + 8 + nonce.length);
    buffer.put(sessionId.getBytes());
    buffer.putLong(timestamp);
    buffer.put(nonce);
    return buffer.array();
  }

  /**
   * Limpa nonces antigos para evitar crescimento ilimitado
   */
  private void cleanupOldNonces() {
    long currentTime = Instant.now().toEpochMilli();
    nonceTimestamps.entrySet().removeIf(entry -> {
      if (currentTime - entry.getValue() > REPLAY_WINDOW_MS * 2) {
        usedNonces.remove(entry.getKey());
        return true;
      }
      return false;
    });
  }

  /**
   * Converte chave pública para Base64
   */
  public String publicKeyToString(PublicKey publicKey) {
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

  /**
   * Converte Base64 para chave pública EC
   */
  public PublicKey stringToECPublicKey(String keyStr) throws Exception {
    byte[] keyBytes = Base64.getDecoder().decode(keyStr);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    return keyFactory.generatePublic(spec);
  }

  /**
   * Converte Base64 para chave pública RSA
   */
  public PublicKey stringToRSAPublicKey(String keyStr) throws Exception {
    byte[] keyBytes = Base64.getDecoder().decode(keyStr);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(spec);
  }

  /**
   * Calcula fingerprint SHA-256 de uma chave pública Base64
   */
  public String calculateFingerprint(String publicKeyBase64) throws Exception {
    byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
    java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(keyBytes);
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Informação de chave de sessão com timestamp
   */
  public static class SessionKeyInfo {
    public final SecretKey key;
    public final long createdAt;
    public final byte[] salt;

    public SessionKeyInfo(SecretKey key, long createdAt, byte[] salt) {
      this.key = key;
      this.createdAt = createdAt;
      this.salt = salt;
    }
  }

  /**
   * Mensagem cifrada com metadados anti-replay
   */
  public static class EncryptedMessage {
    public final byte[] iv;
    public final byte[] ciphertext;
    public final byte[] nonce;
    public final long timestamp;
    public final String sessionId;

    public EncryptedMessage(byte[] iv, byte[] ciphertext, byte[] nonce,
        long timestamp, String sessionId) {
      this.iv = iv;
      this.ciphertext = ciphertext;
      this.nonce = nonce;
      this.timestamp = timestamp;
      this.sessionId = sessionId;
    }

    public byte[] toBytes() {
      ByteBuffer buffer = ByteBuffer.allocate(
          4 + iv.length +
              4 + ciphertext.length +
              4 + nonce.length +
              8 +
              4 + sessionId.length());

      buffer.putInt(iv.length);
      buffer.put(iv);
      buffer.putInt(ciphertext.length);
      buffer.put(ciphertext);
      buffer.putInt(nonce.length);
      buffer.put(nonce);
      buffer.putLong(timestamp);
      buffer.putInt(sessionId.length());
      buffer.put(sessionId.getBytes());

      return buffer.array();
    }

    public static EncryptedMessage fromBytes(byte[] data) {
      ByteBuffer buffer = ByteBuffer.wrap(data);

      int ivLen = buffer.getInt();
      byte[] iv = new byte[ivLen];
      buffer.get(iv);

      int ctLen = buffer.getInt();
      byte[] ciphertext = new byte[ctLen];
      buffer.get(ciphertext);

      int nonceLen = buffer.getInt();
      byte[] nonce = new byte[nonceLen];
      buffer.get(nonce);

      long timestamp = buffer.getLong();

      int sidLen = buffer.getInt();
      byte[] sidBytes = new byte[sidLen];
      buffer.get(sidBytes);
      String sessionId = new String(sidBytes);

      return new EncryptedMessage(iv, ciphertext, nonce,
          timestamp, sessionId);
    }
  }
}
