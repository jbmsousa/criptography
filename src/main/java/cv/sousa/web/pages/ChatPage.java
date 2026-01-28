package cv.sousa.web.pages;

import cv.sousa.server.service.UserService;
import cv.sousa.web.SecureMessagingSession;
import cv.sousa.web.components.ChatPanel;
import io.quarkus.arc.Arc;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.request.mapper.parameter.PageParameters;

public class ChatPage extends BasePage {

    private String chatPartnerId;

    public ChatPage(PageParameters parameters) {
        requireAuthentication();

        chatPartnerId = parameters.get("userId").toString();

        if (chatPartnerId == null || chatPartnerId.isEmpty()) {
            setResponsePage(DashboardPage.class);
            return;
        }
        String partnerName = chatPartnerId;
        cv.sousa.server.model.User user = userService.findByUserId(chatPartnerId).orElse(null);
        if (user != null) {
            partnerName = user.nome;
        }
        add(new Label("chatPartner", "Chat with " + partnerName));

        Label partnerIdLabel = new Label("chatPartnerId", partnerName);
        partnerIdLabel.setOutputMarkupId(true);
        partnerIdLabel.add(new org.apache.wicket.AttributeModifier("data-userid", chatPartnerId));
        add(partnerIdLabel);
        add(new ChatPanel("chatPanel", chatPartnerId));
    }
    UserService userService = Arc.container().instance(UserService.class).get();
    @Override
    protected String getPageTitle() {
        return "Chat with " + chatPartnerId + " - Secure Messaging";
    }

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);
        response.render(JavaScriptHeaderItem.forUrl("/static/js/chat-page.js"));
    }
}
