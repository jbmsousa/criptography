package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.WebPage;

public class LogoutPage extends WebPage {

    public LogoutPage() {
        SecureMessagingSession session = SecureMessagingSession.get();

        if (session.isAuthenticated()) {
            session.signOut();
        }
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        // Load logout script (CSP-safe external file)
        response.render(JavaScriptHeaderItem.forUrl("/static/js/logout.js"));
    }
}
