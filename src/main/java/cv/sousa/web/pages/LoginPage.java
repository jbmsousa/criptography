package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.PropertyModel;

public class LoginPage extends BasePage {

    private String userId;
    private String password;

    public LoginPage() {
        if (SecureMessagingSession.get().isAuthenticated()) {
            setResponsePage(DashboardPage.class);
            return;
        }

        add(new FeedbackPanel("feedback"));

        Form<Void> form = new Form<>("loginForm") {
            @Override
            protected void onSubmit() {
                // Actual authentication is done via JavaScript/REST API
                // This is just for form structure
            }
        };

        form.add(new TextField<>("userId", new PropertyModel<>(this, "userId"))
            .setRequired(true));
        form.add(new PasswordTextField("password", new PropertyModel<>(this, "password"))
            .setRequired(true));

        add(form);
    }

    @Override
    protected String getPageTitle() {
        return "Login - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        response.render(JavaScriptHeaderItem.forUrl("/static/js/crypto.js"));
        response.render(JavaScriptHeaderItem.forUrl("/static/js/auth.js"));
    }
}
