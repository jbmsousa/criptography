package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import de.agilecoders.wicket.core.markup.html.bootstrap.navbar.Navbar;
import de.agilecoders.wicket.core.markup.html.bootstrap.navbar.NavbarButton;
import de.agilecoders.wicket.core.markup.html.bootstrap.navbar.NavbarComponents;
import org.apache.wicket.markup.head.CssHeaderItem;
import org.apache.wicket.markup.head.IHeaderResponse;
import org.apache.wicket.markup.head.JavaScriptHeaderItem;
import org.apache.wicket.markup.head.MetaDataHeaderItem;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.model.Model;

public abstract class BasePage extends WebPage {

    public BasePage() {
        add(new Label("pageTitle", getPageTitle()));
        add(createNavbar());
    }

    protected abstract String getPageTitle();

    @Override
    public void renderHead(IHeaderResponse response) {
        super.renderHead(response);

        // CSP headers are configured via application.properties (quarkus.http.header.*)
        // This is more secure than meta tags as it's enforced by the server

        // Bootstrap 5 CSS
        response.render(CssHeaderItem.forUrl(
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"));

        // Bootstrap Icons
        response.render(CssHeaderItem.forUrl(
            "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css"));

        // Custom CSS
        response.render(CssHeaderItem.forUrl("/static/css/custom.css"));

        // Bootstrap 5 JS
        response.render(JavaScriptHeaderItem.forUrl(
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"));

        // Inject auth data via meta tags (CSP-safe, no inline scripts needed)
        SecureMessagingSession session = SecureMessagingSession.get();
        if (session.isAuthenticated()) {
            response.render(MetaDataHeaderItem.forMetaTag("auth-user-id", session.getUserId()));
            response.render(MetaDataHeaderItem.forMetaTag("auth-token", session.getAuthToken()));
        }

        // Load auth-init.js to read meta tags and store in localStorage
        response.render(JavaScriptHeaderItem.forUrl("/static/js/auth-init.js"));
    }

    protected Navbar createNavbar() {
        Navbar navbar = new Navbar("navbar");
        navbar.setBrandName(Model.of("SecureChat"));
        navbar.setPosition(Navbar.Position.TOP);
        navbar.fluid(true);

        SecureMessagingSession session = SecureMessagingSession.get();

        if (session.isAuthenticated()) {
            navbar.addComponents(NavbarComponents.transform(
                Navbar.ComponentPosition.LEFT,
                new NavbarButton<>(DashboardPage.class, Model.of("Dashboard")),
                new NavbarButton<>(ProfilePage.class, Model.of("Perfil"))
            ));

            navbar.addComponents(NavbarComponents.transform(
                Navbar.ComponentPosition.RIGHT,
                new NavbarButton<>(LogoutPage.class, Model.of("Sair (" + session.getUserId() + ")"))
            ));
        } else {
            navbar.addComponents(NavbarComponents.transform(
                Navbar.ComponentPosition.RIGHT,
                new NavbarButton<>(LoginPage.class, Model.of("Entrar")),
                new NavbarButton<>(RegisterPage.class, Model.of("Registar"))
            ));
        }

        return navbar;
    }

    protected void requireAuthentication() {
        if (!SecureMessagingSession.get().isAuthenticated()) {
            setResponsePage(LoginPage.class);
        }
    }
}
