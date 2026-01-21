package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import cv.sousa.web.components.UserListPanel;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.basic.Label;

public class DashboardPage extends BasePage {

    public DashboardPage() {
        requireAuthentication();

        SecureMessagingSession session = SecureMessagingSession.get();

        add(new Label("welcomeMessage", "Welcome, " + session.getUserId() + "!"));
        add(new UserListPanel("userListPanel"));
    }

    @Override
    protected String getPageTitle() {
        return "Dashboard - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        response.render(JavaScriptHeaderItem.forUrl("/static/js/crypto.js"));
        response.render(JavaScriptHeaderItem.forUrl("/static/js/dashboard.js"));
    }
}
