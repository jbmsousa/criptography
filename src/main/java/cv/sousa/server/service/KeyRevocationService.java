package cv.sousa.server.service;


import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import cv.sousa.server.model.RevokedKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * Serviço de gestão de revogação de chaves
 * Implementa CRL (Certificate Revocation List) simplificado
 */
@ApplicationScoped
public class KeyRevocationService {

  // Cache em memória para verificação rápida
  private final Set<String> revokedKeysCache =
      Collections.synchronizedSet(new HashSet<>());

  // Cache com expiração automática
  private final ConcurrentHashMap<String, LocalDateTime> revocationTimestamps =
      new ConcurrentHashMap<>();

  /**
   * Revoga uma chave pública
   */
  @Transactional
  public RevokedKey revokeKey(String userId, String publicKeyFingerprint,
      String reason) {
    // Verificar se já está revogada
    if (isKeyRevoked(publicKeyFingerprint)) {
      throw new IllegalStateException(
          "Key already revoked for user: " + userId);
    }

    // Criar entrada de revogação
    RevokedKey revokedKey = new RevokedKey();
    revokedKey.userId = userId;
    revokedKey.publicKeyFingerprint = publicKeyFingerprint;
    revokedKey.reason = reason;
    revokedKey.revokedAt = LocalDateTime.now();
    revokedKey.persist();

    // Adicionar ao cache
    revokedKeysCache.add(publicKeyFingerprint);
    revocationTimestamps.put(publicKeyFingerprint, revokedKey.revokedAt);

    System.out.println("🚫 Key revoked: " + userId +
        " (reason: " + reason + ")");

    return revokedKey;
  }

  /**
   * Verifica se uma chave está revogada
   */
  public boolean isKeyRevoked(String publicKeyFingerprint) {
    // Verificar cache primeiro (rápido)
    if (revokedKeysCache.contains(publicKeyFingerprint)) {
      return true;
    }

    // Verificar base de dados
    RevokedKey revoked = RevokedKey.findByFingerprint(publicKeyFingerprint);
    if (revoked != null) {
      // Atualizar cache
      revokedKeysCache.add(publicKeyFingerprint);
      revocationTimestamps.put(publicKeyFingerprint, revoked.revokedAt);
      return true;
    }

    return false;
  }

  /**
   * Obtém lista de revogação (CRL)
   */
  public List<RevokedKey> getRevocationList() {
    return RevokedKey.listAll();
  }

  /**
   * Obtém CRL filtrada por período
   */
  public List<RevokedKey> getRevocationListSince(LocalDateTime since) {
    return RevokedKey.find("revokedAt >= ?1", since).list();
  }

  /**
   * Limpa revogações antigas (após período de retenção)
   */
  @Transactional
  public int cleanupOldRevocations(int retentionDays) {
    LocalDateTime cutoff = LocalDateTime.now().minusDays(retentionDays);

    List<RevokedKey> oldRevocations =
        RevokedKey.find("revokedAt < ?1", cutoff).list();

    for (RevokedKey revoked : oldRevocations) {
      revokedKeysCache.remove(revoked.publicKeyFingerprint);
      revocationTimestamps.remove(revoked.publicKeyFingerprint);
      revoked.delete();
    }

    return oldRevocations.size();
  }

  /**
   * Calcula fingerprint SHA-256 de uma chave pública
   */
  public String calculateFingerprint(String publicKeyBase64)
      throws Exception {
    byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
    java.security.MessageDigest digest =
        java.security.MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(keyBytes);
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Obtém estatísticas de revogação
   */
  public RevocationStats getStats() {
    long total = RevokedKey.count();
    long last24h = RevokedKey.find("revokedAt >= ?1",
        LocalDateTime.now().minusDays(1)).count();
    long last7d = RevokedKey.find("revokedAt >= ?1",
        LocalDateTime.now().minusDays(7)).count();

    return new RevocationStats(total, last24h, last7d);
  }

  /**
   * Força atualização do cache a partir da base de dados
   */
  public void refreshCache() {
    revokedKeysCache.clear();
    revocationTimestamps.clear();

    List<RevokedKey> allRevoked = RevokedKey.listAll();
    for (RevokedKey revoked : allRevoked) {
      revokedKeysCache.add(revoked.publicKeyFingerprint);
      revocationTimestamps.put(revoked.publicKeyFingerprint,
          revoked.revokedAt);
    }

    System.out.println("✓ Cache atualizado: " +
        revokedKeysCache.size() + " chaves revogadas");
  }

  /**
   * Estatísticas de revogação
   */
  public static class RevocationStats {
    public final long totalRevoked;
    public final long revokedLast24Hours;
    public final long revokedLast7Days;

    public RevocationStats(long total, long last24h, long last7d) {
      this.totalRevoked = total;
      this.revokedLast24Hours = last24h;
      this.revokedLast7Days = last7d;
    }
  }
}



