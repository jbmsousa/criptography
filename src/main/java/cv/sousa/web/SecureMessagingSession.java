package cv.sousa.web;

import org.apache.wicket.protocol.http.WebSession;
import org.apache.wicket.request.Request;

public class SecureMessagingSession extends WebSession {

    private String userId;
    private String authToken;
    private String ecdhPrivateKey;
    private String rsaPrivateKey;

    public SecureMessagingSession(Request request) {
        super(request);
    }

    public static SecureMessagingSession get() {
        return (SecureMessagingSession) WebSession.get();
    }

    public boolean isAuthenticated() {
        return userId != null && authToken != null;
    }

    public void signIn(String userId, String authToken) {
        this.userId = userId;
        this.authToken = authToken;
        bind();
    }

    public void signOut() {
        this.userId = null;
        this.authToken = null;
        this.ecdhPrivateKey = null;
        this.rsaPrivateKey = null;
        invalidate();
    }

    public String getUserId() {
        return userId;
    }

    public String getAuthToken() {
        return authToken;
    }

    public void setKeys(String ecdhPrivateKey, String rsaPrivateKey) {
        this.ecdhPrivateKey = ecdhPrivateKey;
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public String getEcdhPrivateKey() {
        return ecdhPrivateKey;
    }

    public String getRsaPrivateKey() {
        return rsaPrivateKey;
    }
}
