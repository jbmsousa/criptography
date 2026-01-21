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
