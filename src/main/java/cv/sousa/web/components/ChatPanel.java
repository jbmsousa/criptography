package cv.sousa.web.components;

import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.TextArea;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.PropertyModel;

public class ChatPanel extends Panel {

    private String messageText;
    private final String chatPartnerId;

    public ChatPanel(String id, String chatPartnerId) {
        super(id);
        this.chatPartnerId = chatPartnerId;

        setOutputMarkupId(true);

        add(new Label("chatPartnerId", chatPartnerId));

        Form<Void> messageForm = new Form<>("messageForm") {
            @Override
            protected void onSubmit() {
                // Message sending handled via JavaScript
            }
        };

        TextArea<String> messageInput = new TextArea<>("messageInput",
            new PropertyModel<>(this, "messageText"));
        messageInput.setOutputMarkupId(true);
        messageForm.add(messageInput);

        add(messageForm);
    }

    public String getMessageText() {
        return messageText;
    }

    public void setMessageText(String messageText) {
        this.messageText = messageText;
    }
}
