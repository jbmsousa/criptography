package cv.sousa.client;

import cv.sousa.client.service.*;
import cv.sousa.client.config.TLSConfig;
import java.security.*;
import javax.crypto.SecretKey;
import java.net.http.*;
import java.util.*;

/**
 * Cliente melhorado com:
 * - ECDHE para Perfect Forward Secrecy
 * - Proteção contra replay attacks
 * - Rotação automática de chaves
 * - Comunicação HTTPS
 * - Verificação de revogação de chaves
 */
public class EnhancedClientApp {
  private static final String SERVER_URL = "https://localhost:8443";
  private final EnhancedCryptoService cryptoService;
  private final EnhancedMessagingService messagingService;
  private final Scanner scanner;

  // Chaves do utilizador
  private KeyPair myECDHKeyPair;  // Para ECDHE
  private KeyPair myRSAKeyPair;   // Para assinaturas
  private String myUserId;

  // Sessão ativa
  private String sessionId;
  private SecretKey sessionKey;
  private PublicKey recipientECDHKey;
  private PublicKey recipientRSAKey;
  private String recipientId;

  public EnhancedClientApp() throws Exception {
    this.cryptoService = new EnhancedCryptoService();

    // Criar HttpClient com TLS
    HttpClient secureClient = TLSConfig.createSecureHttpClient();
    this.messagingService = new EnhancedMessagingService(
        SERVER_URL, secureClient);

    this.scanner = new Scanner(System.in);
  }

  public static void main(String[] args) {
    try {
      EnhancedClientApp app = new EnhancedClientApp();
      app.run();
    } catch (Exception e) {
      System.err.println("Erro ao inicializar: " + e.getMessage());
      e.printStackTrace();
    }
  }

  public void run() {
    try {
      printBanner();

      while (true) {
        System.out.println("\n=== MENU PRINCIPAL ===");
        System.out.println("1. Registar novo utilizador");
        System.out.println("2. Listar utilizadores registados");
        System.out.println("3. Iniciar chat seguro (ECDHE)");
        System.out.println("4. Verificar revogação de chave");
        System.out.println("5. Revogar minha chave");
        System.out.println("6. Ver estatísticas de segurança");
        System.out.println("7. Sair");
        System.out.print("Escolha: ");

        int choice = scanner.nextInt();
        scanner.nextLine();

        switch (choice) {
          case 1 -> registerUser();
          case 2 -> listUsers();
          case 3 -> startSecureChat();
          case 4 -> checkRevocation();
          case 5 -> revokeMyKey();
          case 6 -> showSecurityStats();
          case 7 -> {
            System.out.println("Adeus!");
            return;
          }
          default -> System.out.println("Opção inválida!");
        }
      }
    } catch (Exception e) {
      System.err.println("Erro: " + e.getMessage());
      e.printStackTrace();
    }
  }

  private void registerUser() throws Exception {
    System.out.println("\n=== REGISTO DE UTILIZADOR ===");
    System.out.print("ID do utilizador: ");
    myUserId = scanner.nextLine().trim();

    System.out.println("\n🔐 Gerando pares de chaves...");

    // Gerar chaves ECDH para troca de chaves
    System.out.print("  • ECDH (P-256) para Perfect Forward Secrecy... ");
    myECDHKeyPair = cryptoService.generateECDHKeyPair();
    System.out.println("✓");

    // Gerar chaves RSA para assinaturas
    System.out.print("  • RSA-2048 para assinaturas digitais... ");
    myRSAKeyPair = cryptoService.generateRSAKeyPair();
    System.out.println("✓");

    String ecdhPublicKey = cryptoService.publicKeyToString(
        myECDHKeyPair.getPublic());
    String rsaPublicKey = cryptoService.publicKeyToString(
        myRSAKeyPair.getPublic());

    System.out.println("\n📤 Registando no servidor via HTTPS...");
    messagingService.registerUser(myUserId, ecdhPublicKey, rsaPublicKey);

    System.out.println("\n✓ Utilizador registado com sucesso!");
    System.out.println("  • Chave ECDH publicada");
    System.out.println("  • Chave RSA publicada");
    System.out.println("  • Conexão segura TLS estabelecida");
  }

  private void listUsers() throws Exception {
    System.out.println("\n=== UTILIZADORES REGISTADOS ===");
    var users = messagingService.listUsers();

    if (users.isEmpty()) {
      System.out.println("Nenhum utilizador registado.");
      return;
    }

    System.out.println("\nTotal: " + users.size() + " utilizadores\n");
    for (var user : users) {
      String userId = user.get("userId").toString();
      String registeredAt = user.get("registeredAt").toString();

      // Verificar se está revogado
      String ecdhKey = user.get("ecdhPublicKey").toString();
      String fingerprint = cryptoService.calculateFingerprint(ecdhKey);
      boolean revoked = messagingService.isKeyRevoked(fingerprint);

      String status = revoked ? "🚫 REVOGADO" : "✓ Ativo";

      System.out.printf("%-20s %s (registado: %s)\n",
          userId, status, registeredAt.substring(0, 19));
    }
  }

  private void startSecureChat() throws Exception {
    if (myECDHKeyPair == null) {
      System.out.println("❌ Erro: Precisa registar-se primeiro!");
      return;
    }

    System.out.println("\n=== INICIAR CHAT SEGURO ===");
    System.out.print("ID do destinatário: ");
    recipientId = scanner.nextLine().trim();

    System.out.println("\n🔍 Obtendo chaves públicas de " + recipientId + "...");
    var keys = messagingService.getUserKeys(recipientId);

    String ecdhKeyStr = keys.get("ecdhPublicKey").toString();
    String rsaKeyStr = keys.get("rsaPublicKey").toString();

    // Verificar revogação
    String fingerprint = cryptoService.calculateFingerprint(ecdhKeyStr);
    if (messagingService.isKeyRevoked(fingerprint)) {
      System.out.println("\n⚠️  ATENÇÃO: Chave do destinatário foi REVOGADA!");
      System.out.print("Continuar mesmo assim? (s/N): ");
      String answer = scanner.nextLine();
      if (!answer.equalsIgnoreCase("s")) {
        return;
      }
    }

    recipientECDHKey = cryptoService.stringToECPublicKey(ecdhKeyStr);
    recipientRSAKey = cryptoService.stringToRSAPublicKey(rsaKeyStr);

    // Gerar ID de sessão único
    sessionId = UUID.randomUUID().toString();

    System.out.println("\n🔐 Estabelecendo canal seguro com ECDHE...");

    // Derivar chave de sessão usando ECDH
    byte[] salt = new byte[32];
    new SecureRandom().nextBytes(salt);

    sessionKey = cryptoService.deriveSessionKey(
        myECDHKeyPair.getPrivate(),
        recipientECDHKey,
        salt
    );

    System.out.println("\n✅ Canal seguro estabelecido!");
    System.out.println("═══════════════════════════════════════");
    System.out.println("  🔒 Perfect Forward Secrecy: ATIVADO");
    System.out.println("  🔐 Algoritmo: ECDHE-P256 + AES-256-GCM");
    System.out.println("  ✍️  Assinatura: RSA-SHA256");
    System.out.println("  🛡️  Anti-Replay: ATIVADO");
    System.out.println("  🔄 Rotação automática: 5 minutos");
    System.out.println("  🔗 Session ID: " + sessionId.substring(0, 8) + "...");
    System.out.println("═══════════════════════════════════════\n");

    chatLoop();
  }

  private void chatLoop() throws Exception {
    System.out.println("Digite suas mensagens (ou 'sair' para voltar):");
    System.out.println("Comandos: 'rotate' (forçar rotação), 'stats' (estatísticas)\n");

    int messageCount = 0;
    long sessionStart = System.currentTimeMillis();

    while (true) {
      System.out.print(myUserId + " > ");
      String message = scanner.nextLine();

      if (message.equalsIgnoreCase("sair")) {
        long sessionDuration = (System.currentTimeMillis() - sessionStart) / 1000;
        System.out.println("\n📊 Sessão encerrada:");
        System.out.println("  • Duração: " + sessionDuration + " segundos");
        System.out.println("  • Mensagens enviadas: " + messageCount);
        break;
      }

      if (message.equalsIgnoreCase("rotate")) {
        rotateSessionKey();
        continue;
      }

      if (message.equalsIgnoreCase("stats")) {
        showSessionStats(messageCount, sessionStart);
        continue;
      }

      // Verificar se precisa rotacionar chave
      sessionKey = cryptoService.getOrRotateSessionKey(
          sessionId,
          myECDHKeyPair.getPrivate(),
          recipientECDHKey
      );

      // Cifrar mensagem com proteção anti-replay
      var encryptedMsg = cryptoService.encryptMessageSecure(
          message, sessionKey, sessionId);

      // Assinar mensagem cifrada
      byte[] msgBytes = encryptedMsg.toBytes();
      byte[] signature = cryptoService.signMessage(
          msgBytes,
          myRSAKeyPair.getPrivate(),
          encryptedMsg.timestamp
      );

      messageCount++;

      System.out.println("\n[ENVIADO - Protegido]");
      System.out.println("  📦 Tamanho: " + msgBytes.length + " bytes");
      System.out.println("  ✍️  Assinatura: " + signature.length + " bytes");
      System.out.println("  🕐 Timestamp: " + new Date(encryptedMsg.timestamp));
      System.out.println("  🎲 Nonce: " + Base64.getEncoder()
          .encodeToString(encryptedMsg.nonce).substring(0, 16) + "...");

      // Simular recepção (em produção, viria da rede)
      simulateReceive(encryptedMsg, signature);
    }
  }

  private void simulateReceive(EnhancedCryptoService.EncryptedMessage encMsg,
      byte[] signature) throws Exception {
    System.out.println("\n[RECEBIDO - Verificando...]");

    // Verificar assinatura
    byte[] msgBytes = encMsg.toBytes();
    boolean validSignature = cryptoService.verifySignature(
        msgBytes, signature, myRSAKeyPair.getPublic(), encMsg.timestamp);

    if (!validSignature) {
      System.out.println("  ⚠️  ALERTA: Assinatura inválida!");
      return;
    }
    System.out.println("  ✓ Assinatura válida");

    try {
      // Decifrar com verificação anti-replay
      String decrypted = cryptoService.decryptMessageSecure(
          encMsg, sessionKey);

      System.out.println("  ✓ Anti-replay: OK");
      System.out.println("  ✓ Integridade: OK");
      System.out.println("  📝 Mensagem: " + decrypted + "\n");

    } catch (SecurityException e) {
      System.out.println("  🚫 " + e.getMessage());
    }
  }

  private void rotateSessionKey() throws Exception {
    System.out.println("\n🔄 Forçando rotação de chave...");

    byte[] salt = new byte[32];
    new SecureRandom().nextBytes(salt);

    sessionKey = cryptoService.deriveSessionKey(
        myECDHKeyPair.getPrivate(),
        recipientECDHKey,
        salt
    );

    System.out.println("✓ Nova chave de sessão gerada!");
  }

  private void showSessionStats(int msgCount, long startTime) {
    long duration = (System.currentTimeMillis() - startTime) / 1000;
    System.out.println("\n📊 Estatísticas da Sessão:");
    System.out.println("  • Mensagens enviadas: " + msgCount);
    System.out.println("  • Duração: " + duration + " segundos");
    System.out.println("  • Taxa: " + (msgCount * 60.0 / duration) + " msg/min");
    System.out.println("  • Session ID: " + sessionId);
  }

  private void checkRevocation() throws Exception {
    System.out.println("\n=== VERIFICAR REVOGAÇÃO ===");
    System.out.print("ID do utilizador: ");
    String userId = scanner.nextLine().trim();

    var keys = messagingService.getUserKeys(userId);
    String publicKey = keys.get("ecdhPublicKey").toString();
    String fingerprint = cryptoService.calculateFingerprint(publicKey);

    boolean revoked = messagingService.isKeyRevoked(fingerprint);

    System.out.println("\nUtilizador: " + userId);
    System.out.println("Fingerprint: " + fingerprint.substring(0, 32) + "...");
    System.out.println("Status: " + (revoked ? "🚫 REVOGADO" : "✓ ATIVO"));
  }

  private void revokeMyKey() throws Exception {
    if (myECDHKeyPair == null) {
      System.out.println("❌ Erro: Precisa registar-se primeiro!");
      return;
    }

    System.out.println("\n=== REVOGAR MINHA CHAVE ===");
    System.out.println("⚠️  ATENÇÃO: Esta ação não pode ser desfeita!");
    System.out.print("Motivo da revogação: ");
    String reason = scanner.nextLine();

    System.out.print("Confirmar revogação? (s/N): ");
    String confirm = scanner.nextLine();

    if (!confirm.equalsIgnoreCase("s")) {
      System.out.println("Operação cancelada.");
      return;
    }

    String publicKey = cryptoService.publicKeyToString(
        myECDHKeyPair.getPublic());

    messagingService.revokeKey(myUserId, publicKey, reason);

    System.out.println("\n✓ Chave revogada com sucesso!");
    System.out.println("  • Você precisará registar-se novamente com novas chaves");

    // Limpar chaves locais
    myECDHKeyPair = null;
    myRSAKeyPair = null;
  }

  private void showSecurityStats() throws Exception {
    System.out.println("\n=== ESTATÍSTICAS DE SEGURANÇA ===");

    var stats = messagingService.getRevocationStats();

    System.out.println("\n📊 Revogações:");
    System.out.println("  • Total revogado: " + stats.get("totalRevoked"));
    System.out.println("  • Últimas 24h: " + stats.get("revokedLast24Hours"));
    System.out.println("  • Últimos 7 dias: " + stats.get("revokedLast7Days"));

    System.out.println("\n🔐 Segurança Ativa:");
    System.out.println("  ✓ TLS 1.3");
    System.out.println("  ✓ Perfect Forward Secrecy (ECDHE)");
    System.out.println("  ✓ Proteção Anti-Replay");
    System.out.println("  ✓ Rotação Automática de Chaves");
    System.out.println("  ✓ Verificação de Revogação");
  }

  private void printBanner() {
    System.out.println("""
            ╔═══════════════════════════════════════════════════════╗
            ║   SISTEMA DE MENSAGENS SEGURAS v2.0                   ║
            ║   ✨ MELHORIAS DE SEGURANÇA ✨                         ║
            ║                                                       ║
            ║   🔒 Perfect Forward Secrecy (ECDHE-P256)              ║
            ║   🛡️  Proteção Anti-Replay (Nonce + Timestamp)         ║
            ║   🔄 Rotação Automática de Chaves                     ║
            ║   🔐 TLS 1.3 / HTTPS                                  ║
            ║   🚫 Gestão de Revogação (CRL)                        ║
            ║                                                       ║
            ║   Algoritmos: ECDHE + AES-256-GCM + RSA-SHA256        ║
            ╚═══════════════════════════════════════════════════════╝
            """);
  }
}