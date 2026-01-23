package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.panel.FeedbackPanel;

public class RegisterPage extends BasePage {

    public RegisterPage() {
        if (SecureMessagingSession.get().isAuthenticated()) {
            setResponsePage(DashboardPage.class);
            return;
        }

        add(new FeedbackPanel("feedback"));
        // Form is pure HTML - no Wicket component needed, JS handles submission
    }

    @Override
    protected String getPageTitle() {
        return "Register - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        // Load registration JS for key generation
        response.render(JavaScriptHeaderItem.forUrl("/static/js/register.js"));
    }
}