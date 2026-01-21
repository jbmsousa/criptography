package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.markup.html.WebPage;

public class LogoutPage extends WebPage {

    public LogoutPage() {
        SecureMessagingSession session = SecureMessagingSession.get();

        if (session.isAuthenticated()) {
            // Call logout API via JavaScript, then invalidate session
            session.signOut();
        }

        setResponsePage(LoginPage.class);
    }
}
