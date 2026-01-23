package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import cv.sousa.web.components.ChatPanel;
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

        add(new Label("chatPartner", "Chat with " + chatPartnerId));
        add(new Label("chatPartnerId", chatPartnerId).setOutputMarkupId(true));
        add(new ChatPanel("chatPanel", chatPartnerId));
    }

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
