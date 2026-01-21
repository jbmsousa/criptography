# 🚀 Guia Rápido de Implementação - 15 Minutos

## Passo 1: Criar Projeto (2 min)

```bash
mvn io.quarkus:quarkus-maven-plugin:3.6.4:create \
    -DprojectGroupId=org.crypto \
    -DprojectArtifactId=crypto-messaging-v2 \
    -Dextensions="resteasy-reactive-jackson,hibernate-orm-panache,jdbc-h2"

cd crypto-messaging-v2
```

## Passo 2: Configurar TLS (3 min)

### Criar script de setup

```bash
cat > setup-tls.sh << 'EOF'
#!/bin/bash
keytool -genkeypair \
    -alias crypto-server \
    -keyalg RSA -keysize 2048 \
    -storetype PKCS12 \
    -keystore src/main/resources/keystore.p12 \
    -storepass changeit \
    -validity 365 \
    -dname "CN=localhost, OU=Dev, O=Crypto, C=PT" \
    -ext "SAN=dns:localhost,ip:127.0.0.1"

keytool -exportcert \
    -alias crypto-server \
    -keystore src/main/resources/keystore.p12 \
    -storepass changeit \
    -file src/main/resources/server-cert.cer \
    -rfc

keytool -importcert \
    -alias crypto-server \
    -file src/main/resources/server-cert.cer \
    -keystore src/main/resources/truststore.p12 \
    -storepass changeit \
    -storetype PKCS12 \
    -noprompt

echo "✅ TLS configurado com sucesso!"
EOF

chmod +x setup-tls.sh
./setup-tls.sh
```

### Atualizar application.properties

```properties
# src/main/resources/application.properties
quarkus.datasource.db-kind=h2
quarkus.datasource.jdbc.url=jdbc:h2:mem:cryptodb
quarkus.hibernate-orm.database.generation=drop-and-create

quarkus.http.ssl.certificate.key-store-file=keystore.p12
quarkus.http.ssl.certificate.key-store-password=changeit
quarkus.http.ssl-port=8443
quarkus.http.insecure-requests=redirect
quarkus.http.ssl.protocols=TLSv1.2,TLSv1.3
quarkus.http.cors=true
```

## Passo 3: Copiar Classes (5 min)

### Estrutura de diretórios

```bash
mkdir -p src/main/java/org/crypto/{server/{model,service,resource},client/{model,service,config}}
```

### Classes do Servidor

**User.java** → `src/main/java/org/crypto/server/model/User.java`
```java
package org.crypto.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User extends PanacheEntity {
    @Column(unique = true, nullable = false)
    public String userId;
    
    @Column(columnDefinition = "TEXT")
    public String ecdhPublicKey;
    
    @Column(columnDefinition = "TEXT")
    public String rsaPublicKey;
    
    public LocalDateTime registeredAt = LocalDateTime.now();
    
    public static User findByUserId(String userId) {
        return find("userId", userId).firstResult();
    }
}
```

**RevokedKey.java** → `src/main/java/org/crypto/server/model/RevokedKey.java`
```java
package org.crypto.server.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "revoked_keys")
public class RevokedKey extends PanacheEntity {
    @Column(unique = true, nullable = false)
    public String publicKeyFingerprint;
    
    public String userId;
    public String reason;
    public LocalDateTime revokedAt = LocalDateTime.now();
    
    public static RevokedKey findByFingerprint(String fp) {
        return find("publicKeyFingerprint", fp).firstResult();
    }
}
```

**KeyRegistryResource.java** → `src/main/java/org/crypto/server/resource/KeyRegistryResource.java`
```java
package org.crypto.server.resource;

import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.crypto.server.model.User;
import java.util.List;

@Path("/api/keys")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class KeyRegistryResource {
    
    @POST
    @Path("/register")
    @Transactional
    public Response register(RegRequest req) {
        if (User.findByUserId(req.userId) != null)
            return Response.status(409).entity("User exists").build();
        
        User user = new User();
        user.userId = req.userId;
        user.ecdhPublicKey = req.ecdhPublicKey;
        user.rsaPublicKey = req.rsaPublicKey;
        user.persist();
        
        return Response.status(201).entity(user).build();
    }
    
    @GET
    @Path("/{userId}")
    public Response getUser(@PathParam("userId") String userId) {
        User user = User.findByUserId(userId);
        return user != null ? Response.ok(user).build() 
                            : Response.status(404).build();
    }
    
    @GET
    @Path("/users")
    public List<User> listUsers() {
        return User.listAll();
    }
    
    public static class RegRequest {
        public String userId;
        public String ecdhPublicKey;
        public String rsaPublicKey;
    }
}
```

**RevocationResource.java** → `src/main/java/org/crypto/server/resource/RevocationResource.java`
```java
package org.crypto.server.resource;

import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.crypto.server.model.RevokedKey;
import java.security.MessageDigest;
import java.util.*;

@Path("/api/revocation")
@Produces(MediaType.APPLICATION_JSON)
public class RevocationResource {
    
    @POST
    @Path("/revoke")
    @Transactional
    public Response revoke(RevRequest req) throws Exception {
        String fp = fingerprint(req.publicKey);
        
        if (RevokedKey.findByFingerprint(fp) != null)
            return Response.status(409).build();
        
        RevokedKey rk = new RevokedKey();
        rk.userId = req.userId;
        rk.publicKeyFingerprint = fp;
        rk.reason = req.reason;
        rk.persist();
        
        return Response.ok(rk).build();
    }
    
    @GET
    @Path("/check/{fp}")
    public Response check(@PathParam("fp") String fp) {
        boolean revoked = RevokedKey.findByFingerprint(fp) != null;
        return Response.ok(Map.of("revoked", revoked)).build();
    }
    
    @GET
    @Path("/stats")
    public Response stats() {
        return Response.ok(Map.of(
            "totalRevoked", RevokedKey.count()
        )).build();
    }
    
    private String fingerprint(String key) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(Base64.getDecoder().decode(key));
        return Base64.getEncoder().encodeToString(hash);
    }
    
    public static class RevRequest {
        public String userId, publicKey, reason;
    }
}
```

### Classes do Cliente (TLSConfig.java)

**TLSConfig.java** → `src/main/java/org/crypto/client/config/TLSConfig.java`
```java
package org.crypto.client.config;

import javax.net.ssl.*;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.security.*;

public class TLSConfig {
    public static HttpClient createSecureHttpClient() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = TLSConfig.class.getClassLoader()
                .getResourceAsStream("truststore.p12")) {
            trustStore.load(is, "changeit".toCharArray());
        }
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        
        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();
    }
}
```

## Passo 4: Testar Sistema (5 min)

### Terminal 1 - Iniciar Servidor

```bash
./mvnw quarkus:dev
```

Aguarde até ver:
```
Listening on: https://localhost:8443
```

### Terminal 2 - Testar API

```bash
# Testar HTTPS
curl -k https://localhost:8443/api/keys/users

# Registrar usuário de teste
curl -k -X POST https://localhost:8443/api/keys/register \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "alice",
    "ecdhPublicKey": "test-ecdh-key",
    "rsaPublicKey": "test-rsa-key"
  }'

# Verificar registro
curl -k https://localhost:8443/api/keys/alice
```

## ✅ Checklist de Funcionalidades

- [ ] Servidor inicia em HTTPS (porta 8443)
- [ ] Registro de usuários funciona
- [ ] Consulta de chaves funciona
- [ ] Lista de usuários funciona
- [ ] API de revogação responde
- [ ] TLS configurado corretamente

## 🎯 Próximos Passos

### Para Cliente Completo

1. Copiar **EnhancedCryptoService.java** (do artifact anterior)
2. Copiar **EnhancedClientApp.java** (do artifact anterior)
3. Compilar: `mvn clean compile`
4. Executar: `mvn exec:java -Dexec.mainClass="org.crypto.client.EnhancedClientApp"`

### Para Demonstração

1. Abrir 2 terminais para clientes
2. Registrar "alice" no Terminal 2
3. Registrar "bob" no Terminal 3
4. Iniciar chat entre alice e bob
5. Demonstrar:
   - Cifra de mensagens
   - Assinaturas digitais
   - Proteção anti-replay
   - Rotação de chaves
   - Revogação de chaves

## 📝 Comandos Úteis

```bash
# Ver logs do servidor
./mvnw quarkus:dev

# Limpar e recompilar
mvn clean compile

# Executar testes
mvn test

# Gerar relatório de dependências
mvn dependency:tree

# Verificar certificados
keytool -list -v -keystore src/main/resources/keystore.p12 -storepass changeit

# Verificar TLS do servidor
openssl s_client -connect localhost:8443 -showcerts
```

## 🐛 Troubleshooting

### Erro: "Unable to find valid certification path"

```bash
# Recriar truststore
rm src/main/resources/truststore.p12
./setup-tls.sh
```

### Erro: "Address already in use"

```bash
# Matar processo na porta 8443
lsof -ti:8443 | xargs kill -9
```

### Erro: "H2 database locked"

```bash
# Limpar banco
rm -rf ~/crypto*
```

## 📚 Documentação Adicional

- **README.md** - Documentação completa
- **SECURITY_IMPROVEMENTS.md** - Análise de melhorias
- Artifacts do Claude - Código fonte completo
- Guia interativo - Navegação por componentes

## 🎓 Para o Relatório

### Seções Recomendadas

1. **Introdução** (1-2 páginas)
   - Motivação
   - Objetivos
   - Contribuições

2. **Arquitetura** (2-3 páginas)
   - Diagrama de componentes
   - Fluxo de comunicação
   - Tecnologias usadas

3. **Implementação Criptográfica** (3-4 páginas)
   - ECDHE e PFS
   - AES-GCM
   - RSA signatures
   - Anti-replay
   - TLS

4. **Gestão de Chaves** (2-3 páginas)
   - Geração
   - Distribuição
   - Rotação
   - Revogação

5. **Análise de Segurança** (2-3 páginas)
   - Propriedades garantidas
   - Ataques mitigados
   - Limitações
   - Comparação v1.0 vs v2.0

6. **Conclusão** (1 página)
   - Resultados
   - Melhorias futuras

### Diagramas Essenciais

1. Arquitetura do sistema
2. Fluxo de registro
3. Fluxo ECDHE
4. Fluxo de mensagem com anti-replay
5. Processo de revogação

---

**Tempo total estimado**: 15-20 minutos para setup básico + teste

**Para implementação completa**: Copiar todos os arquivos dos artifacts anteriores

**Boa sorte com o projeto! 🚀🔐**
