package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.PropertyModel;

public class RegisterPage extends BasePage {

    private String userId;
    private String password;
    private String confirmPassword;

    public RegisterPage() {
        if (SecureMessagingSession.get().isAuthenticated()) {
            setResponsePage(DashboardPage.class);
            return;
        }

        add(new FeedbackPanel("feedback"));

        Form<Void> form = new Form<>("registerForm") {
            @Override
            protected void onSubmit() {
                // Registration handled via JavaScript
            }
        };

        form.add(new TextField<>("userId", new PropertyModel<>(this, "userId"))
            .setRequired(true));
        form.add(new PasswordTextField("password", new PropertyModel<>(this, "password"))
            .setRequired(true));
        form.add(new PasswordTextField("confirmPassword", new PropertyModel<>(this, "confirmPassword"))
            .setRequired(true));

        add(form);
    }

    @Override
    protected String getPageTitle() {
        return "Register - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        response.render(JavaScriptHeaderItem.forUrl("/static/js/crypto.js"));
        response.render(JavaScriptHeaderItem.forUrl("/static/js/auth.js"));
    }
}
