package eu.europa.ec.dgc.gateway.config;

import eu.europa.ec.dgc.gateway.utils.DgcMdc;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class MdcCleanupInterceptor implements HandlerInterceptor {

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
        throws Exception {

        // Clean Up MDC after each Request.
        DgcMdc.clear();
    }
}
