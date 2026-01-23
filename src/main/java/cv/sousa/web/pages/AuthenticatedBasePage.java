package cv.sousa.web.pages;

import cv.sousa.web.SecureMessagingSession;
import org.apache.wicket.RestartResponseAtInterceptPageException;

public abstract class AuthenticatedBasePage extends BasePage {

  public AuthenticatedBasePage() {
    // Verificar se está autenticado
    if (!SecureMessagingSession.get().isAuthenticated()) {
      // Redirecionar para login se não estiver autenticado
      throw new RestartResponseAtInterceptPageException(LoginPage.class);
    }
  }

  /**
   * Retorna o userId do usuário autenticado
   */
  protected String getCurrentUserId() {
    return SecureMessagingSession.get().getUserId();
  }
}