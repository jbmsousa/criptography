package cv.sousa.web;

import cv.sousa.web.pages.*;
import de.agilecoders.wicket.core.Bootstrap;
import de.agilecoders.wicket.core.settings.BootstrapSettings;
import org.apache.wicket.Page;
import org.apache.wicket.Session;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.Request;
import org.apache.wicket.request.Response;
import org.apache.wicket.csp.CSPDirective;
import org.apache.wicket.csp.CSPDirectiveSrcValue;

public class WicketApplication extends WebApplication {

    @Override
    public Class<? extends Page> getHomePage() {
        return LoginPage.class;
    }

    @Override
    public Session newSession(Request request, Response response) {
        return new SecureMessagingSession(request);
    }

    @Override
    public void init() {
        super.init();

        // Configure Bootstrap
        BootstrapSettings settings = new BootstrapSettings();
        Bootstrap.install(this, settings);

        // Configure CSP for WebSocket and inline scripts
        getCspSettings().blocking()
            .add(CSPDirective.STYLE_SRC, CSPDirectiveSrcValue.SELF)
            .add(CSPDirective.STYLE_SRC, CSPDirectiveSrcValue.UNSAFE_INLINE)
            .add(CSPDirective.STYLE_SRC, "https://cdn.jsdelivr.net")
            .add(CSPDirective.SCRIPT_SRC, CSPDirectiveSrcValue.SELF)
            .add(CSPDirective.SCRIPT_SRC, CSPDirectiveSrcValue.UNSAFE_INLINE)
            .add(CSPDirective.SCRIPT_SRC, CSPDirectiveSrcValue.UNSAFE_EVAL)
            .add(CSPDirective.SCRIPT_SRC, "https://cdn.jsdelivr.net")
            .add(CSPDirective.CONNECT_SRC, CSPDirectiveSrcValue.SELF)
            .add(CSPDirective.CONNECT_SRC, "ws://localhost:8080")
            .add(CSPDirective.CONNECT_SRC, "wss://localhost:8080")
            .add(CSPDirective.FONT_SRC, CSPDirectiveSrcValue.SELF)
            .add(CSPDirective.FONT_SRC, "https://cdn.jsdelivr.net")
            .add(CSPDirective.IMG_SRC, CSPDirectiveSrcValue.SELF)
            .add(CSPDirective.IMG_SRC, "data:");

        // Mount pages
        mountPage("/login", LoginPage.class);
        mountPage("/register", RegisterPage.class);
        mountPage("/dashboard", DashboardPage.class);
        mountPage("/chat/${userId}", ChatPage.class);
        mountPage("/profile", ProfilePage.class);
        mountPage("/logout", LogoutPage.class);

        // Development mode settings
        getDebugSettings().setAjaxDebugModeEnabled(false);
        getMarkupSettings().setStripWicketTags(true);
    }
}
