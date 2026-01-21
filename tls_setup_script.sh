#!/bin/bash

# ============================================
# Script de Setup TLS/HTTPS para Servidor
# Gera certificados auto-assinados para desenvolvimento
# ============================================

set -e

echo "🔐 Configurando TLS/HTTPS para o servidor..."
echo ""

# Cores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Variáveis
KEYSTORE_FILE="keystore.p12"
KEYSTORE_PASS="changeit"
KEY_ALIAS="crypto-server"
VALIDITY_DAYS=365
CN="localhost"

# Diretório de recursos
RESOURCES_DIR="src/main/resources"
mkdir -p "$RESOURCES_DIR"

# ============================================
# 1. Verificar se keytool está disponível
# ============================================
if ! command -v keytool &> /dev/null; then
    echo -e "${RED}❌ keytool não encontrado. Instale o JDK.${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} keytool encontrado"

# ============================================
# 2. Remover keystore existente (se houver)
# ============================================
if [ -f "$RESOURCES_DIR/$KEYSTORE_FILE" ]; then
    echo -e "${YELLOW}⚠ Keystore existente encontrado. Removendo...${NC}"
    rm "$RESOURCES_DIR/$KEYSTORE_FILE"
fi

# ============================================
# 3. Gerar keystore com certificado auto-assinado
# ============================================
echo ""
echo "📝 Gerando certificado auto-assinado..."
echo ""

keytool -genkeypair \
    -alias "$KEY_ALIAS" \
    -keyalg RSA \
    -keysize 2048 \
    -storetype PKCS12 \
    -keystore "$RESOURCES_DIR/$KEYSTORE_FILE" \
    -storepass "$KEYSTORE_PASS" \
    -validity "$VALIDITY_DAYS" \
    -dname "CN=$CN, OU=Development, O=CryptoMessaging, L=City, ST=State, C=PT" \
    -ext "SAN=dns:localhost,ip:127.0.0.1" \
    -v

echo ""
echo -e "${GREEN}✓${NC} Certificado gerado com sucesso!"

# ============================================
# 4. Exportar certificado público (para clientes)
# ============================================
echo ""
echo "📤 Exportando certificado público..."

keytool -exportcert \
    -alias "$KEY_ALIAS" \
    -keystore "$RESOURCES_DIR/$KEYSTORE_FILE" \
    -storepass "$KEYSTORE_PASS" \
    -file "$RESOURCES_DIR/server-cert.cer" \
    -rfc

echo -e "${GREEN}✓${NC} Certificado público exportado: $RESOURCES_DIR/server-cert.cer"

# ============================================
# 5. Criar truststore para clientes
# ============================================
echo ""
echo "🔑 Criando truststore para clientes..."

TRUSTSTORE_FILE="truststore.p12"
TRUSTSTORE_PASS="changeit"

if [ -f "$RESOURCES_DIR/$TRUSTSTORE_FILE" ]; then
    rm "$RESOURCES_DIR/$TRUSTSTORE_FILE"
fi

keytool -importcert \
    -alias "$KEY_ALIAS" \
    -file "$RESOURCES_DIR/server-cert.cer" \
    -keystore "$RESOURCES_DIR/$TRUSTSTORE_FILE" \
    -storepass "$TRUSTSTORE_PASS" \
    -storetype PKCS12 \
    -noprompt

echo -e "${GREEN}✓${NC} Truststore criado: $RESOURCES_DIR/$TRUSTSTORE_FILE"

# ============================================
# 6. Listar informações do certificado
# ============================================
echo ""
echo "📋 Informações do certificado:"
echo "================================"
keytool -list \
    -keystore "$RESOURCES_DIR/$KEYSTORE_FILE" \
    -storepass "$KEYSTORE_PASS" \
    -v | head -20

# ============================================
# 7. Criar arquivo de configuração para cliente
# ============================================
echo ""
echo "📝 Criando configuração para cliente..."

cat > "$RESOURCES_DIR/client-tls-config.properties" << EOF
# Configuração TLS para Cliente
# ================================

# URL do servidor HTTPS
server.url=https://localhost:8443

# Truststore (contém certificado do servidor)
truststore.path=$TRUSTSTORE_FILE
truststore.password=$TRUSTSTORE_PASS
truststore.type=PKCS12

# Configurações SSL
ssl.protocol=TLSv1.3
ssl.enabled-protocols=TLSv1.2,TLSv1.3

# Validação de hostname (desabilitar apenas para desenvolvimento)
ssl.hostname-verification=false
EOF

echo -e "${GREEN}✓${NC} Configuração criada: $RESOURCES_DIR/client-tls-config.properties"

# ============================================
# 8. Criar helper class para cliente
# ============================================
echo ""
echo "📝 Criando classe helper para cliente Java..."

mkdir -p "src/main/java/org/crypto/client/config"

cat > "src/main/java/org/crypto/client/config/TLSConfig.java" << 'EOJAVA'
package org.crypto.client.config;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;

/**
 * Configuração TLS para cliente
 */
public class TLSConfig {
    
    public static SSLContext createSSLContext(String truststorePath, 
                                             String truststorePassword) 
            throws Exception {
        // Carregar truststore
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = TLSConfig.class.getClassLoader()
                .getResourceAsStream(truststorePath)) {
            trustStore.load(is, truststorePassword.toCharArray());
        }
        
        // Criar TrustManager
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        // Criar SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        
        return sslContext;
    }
    
    public static HttpClient createSecureHttpClient() throws Exception {
        SSLContext sslContext = createSSLContext(
            "truststore.p12", 
            "changeit");
        
        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();
    }
}
EOJAVA

echo -e "${GREEN}✓${NC} Classe TLSConfig criada"

# ============================================
# 9. Resumo
# ============================================
echo ""
echo "═══════════════════════════════════════════════"
echo -e "${GREEN}✓ Setup TLS/HTTPS concluído com sucesso!${NC}"
echo "═══════════════════════════════════════════════"
echo ""
echo "📁 Arquivos gerados:"
echo "  • $RESOURCES_DIR/$KEYSTORE_FILE (keystore do servidor)"
echo "  • $RESOURCES_DIR/$TRUSTSTORE_FILE (truststore para clientes)"
echo "  • $RESOURCES_DIR/server-cert.cer (certificado público)"
echo "  • $RESOURCES_DIR/client-tls-config.properties (config)"
echo ""
echo "🚀 Próximos passos:"
echo "  1. Servidor: ./mvnw quarkus:dev"
echo "  2. Acesse: https://localhost:8443"
echo ""
echo "⚠️  AVISOS:"
echo "  • Certificado auto-assinado - apenas para desenvolvimento"
echo "  • Para produção, use certificados CA válidos"
echo "  • Navegadores mostrarão aviso de segurança (esperado)"
echo ""
echo "🔐 Credenciais:"
echo "  • Keystore password: $KEYSTORE_PASS"
echo "  • Truststore password: $TRUSTSTORE_PASS"
echo ""

# ============================================
# 10. Instruções para testar
# ============================================
cat > "TEST_TLS.md" << 'EOMD'
# Testando HTTPS

## 1. Iniciar Servidor
```bash
./mvnw quarkus:dev
```

## 2. Testar com curl
```bash
# Aceitar certificado auto-assinado
curl -k https://localhost:8443/api/keys/users

# Ou especificar CA
curl --cacert src/main/resources/server-cert.cer \
     https://localhost:8443/api/keys/users
```

## 3. Testar no Navegador
```
https://localhost:8443/q/dev/
```
⚠️ Aceite o aviso de certificado auto-assinado

## 4. Verificar TLS
```bash
openssl s_client -connect localhost:8443 -showcerts
```

## 5. Cliente Java
```java
HttpClient client = TLSConfig.createSecureHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://localhost:8443/api/keys/users"))
    .GET()
    .build();
HttpResponse<String> response = client.send(request, 
    HttpResponse.BodyHandlers.ofString());
```
EOMD

echo -e "${GREEN}✓${NC} Instruções de teste criadas: TEST_TLS.md"
echo ""
ANTML:parameter>