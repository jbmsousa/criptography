package cv.sousa.web.components;

import cv.sousa.web.SecureMessagingSession;
import cv.sousa.web.pages.ChatPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.link.BookmarkablePageLink;
import org.apache.wicket.markup.html.list.ListItem;
import org.apache.wicket.markup.html.list.ListView;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.LoadableDetachableModel;
import org.apache.wicket.request.mapper.parameter.PageParameters;

import java.util.ArrayList;
import java.util.List;

public class UserListPanel extends Panel {

    public UserListPanel(String id) {
        super(id);

        // User list loaded via JavaScript from REST API
        ListView<UserInfo> userList = new ListView<>("userList",
            new LoadableDetachableModel<List<UserInfo>>() {
                @Override
                protected List<UserInfo> load() {
                    // This will be populated via JavaScript
                    return new ArrayList<>();
                }
            }) {
            @Override
            protected void populateItem(ListItem<UserInfo> item) {
                UserInfo user = item.getModelObject();

                PageParameters params = new PageParameters();
                params.add("userId", user.userId);

                BookmarkablePageLink<Void> chatLink = new BookmarkablePageLink<>("chatLink", ChatPage.class, params);
                chatLink.add(new Label("userName", user.userId));

                item.add(chatLink);
                item.add(new Label("status", user.isOnline ? "Online" : "Offline")
                    .add(new org.apache.wicket.AttributeModifier("class",
                        user.isOnline ? "badge bg-success" : "badge bg-secondary")));
                item.add(new Label("keyFingerprint", user.keyFingerprint));
            }
        };

        add(userList);
    }

    public static class UserInfo {
        public String userId;
        public boolean isOnline;
        public String keyFingerprint;

        public UserInfo(String userId, boolean isOnline, String keyFingerprint) {
            this.userId = userId;
            this.isOnline = isOnline;
            this.keyFingerprint = keyFingerprint;
        }
    }
}
