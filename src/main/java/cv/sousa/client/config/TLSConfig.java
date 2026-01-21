package cv.sousa.client.config;

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