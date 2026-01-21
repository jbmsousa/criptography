package cv.sousa.web.components;

import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.Model;

public class KeyInfoPanel extends Panel {

    public KeyInfoPanel(String id) {
        super(id);
        setOutputMarkupId(true);

        // These values will be populated via JavaScript from local storage
        add(new Label("ecdhFingerprint", Model.of("Loading...")).setOutputMarkupId(true));
        add(new Label("rsaFingerprint", Model.of("Loading...")).setOutputMarkupId(true));
        add(new Label("keyCreatedAt", Model.of("Loading...")).setOutputMarkupId(true));
    }
}
