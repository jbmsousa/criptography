package cv.sousa.web.pages;

import cv.sousa.server.service.AuthService;
import cv.sousa.web.SecureMessagingSession;
import io.quarkus.arc.Arc;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.PasswordTextField;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.PropertyModel;

import java.util.Optional;

public class LoginPage extends BasePage {

    private String userId;
    private String password;

    public LoginPage() {
        // Se já está autenticado, redirecionar para dashboard
        if (SecureMessagingSession.get().isAuthenticated()) {
            setResponsePage(DashboardPage.class);
            return;
        }

        add(new FeedbackPanel("feedback"));

        Form<Void> loginForm = new Form<>("loginForm") {
            @Override
            protected void onSubmit() {
                handleLogin();
            }
        };

        loginForm.add(new TextField<>("userId", new PropertyModel<>(this, "userId"))
            .setRequired(true));
        loginForm.add(new PasswordTextField("password", new PropertyModel<>(this, "password"))
            .setRequired(true));

        add(loginForm);
    }

    private AuthService getAuthService() {
        return Arc.container().instance(AuthService.class).get();
    }

    private void handleLogin() {
        if (userId == null || password == null) {
            error("User ID and Password are required");
            return;
        }

        // Use AuthService.login which returns Optional<String> token
        Optional<String> tokenOpt = getAuthService().login(userId, password);

        if (tokenOpt.isPresent()) {
            // Autenticação bem-sucedida
            SecureMessagingSession.get().signIn(userId, tokenOpt.get());

            // Redirecionar para dashboard
            setResponsePage(DashboardPage.class);
        } else {
            // Autenticação falhou
            error("Invalid User ID or Password");
        }
    }

    @Override
    protected String getPageTitle() {
        return "Login - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        // Add login.js for localStorage key checking
        response.render(JavaScriptHeaderItem.forUrl("/static/js/login.js"));
    }
}