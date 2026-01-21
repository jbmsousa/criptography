package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import cv.sousa.web.components.KeyInfoPanel;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Button;
import org.apache.wicket.markup.html.form.Form;

public class ProfilePage extends BasePage {

    public ProfilePage() {
        requireAuthentication();

        SecureMessagingSession session = SecureMessagingSession.get();

        add(new Label("userId", session.getUserId()));
        add(new KeyInfoPanel("keyInfoPanel"));

        // Key regeneration form
        Form<Void> keyForm = new Form<>("keyForm");
        keyForm.add(new Button("regenerateKeys") {
            @Override
            public void onSubmit() {
                // Key regeneration handled via JavaScript
            }
        });
        add(keyForm);

        // Revocation form
        Form<Void> revokeForm = new Form<>("revokeForm");
        revokeForm.add(new Button("revokeKeys") {
            @Override
            public void onSubmit() {
                // Key revocation handled via JavaScript
            }
        });
        add(revokeForm);
    }

    @Override
    protected String getPageTitle() {
        return "Profile - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        response.render(JavaScriptHeaderItem.forUrl("/static/js/crypto.js"));
        response.render(JavaScriptHeaderItem.forUrl("/static/js/profile.js"));
    }
}
