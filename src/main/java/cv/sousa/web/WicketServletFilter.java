package cv.sousa.web;

import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.annotation.WebInitParam;
import org.apache.wicket.protocol.http.WicketFilter;

@WebFilter(
    urlPatterns = "/*",
    initParams = {
        @WebInitParam(name = "applicationClassName", value = "cv.sousa.web.WicketApplication"),
        @WebInitParam(name = "filterMappingUrlPattern", value = "/*")
    }
)
public class WicketServletFilter extends WicketFilter {
}
