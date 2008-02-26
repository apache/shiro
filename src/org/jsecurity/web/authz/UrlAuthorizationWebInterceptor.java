package org.jsecurity.web.authz;

import org.jsecurity.SecurityManager;
import org.jsecurity.web.WebInterceptor;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Feb 25, 2008 7:03:25 PM
 */
public class UrlAuthorizationWebInterceptor implements WebInterceptor {

    private SecurityManager securityManager;
    private String urls;
    private String unauthorizedPage;

    public UrlAuthorizationWebInterceptor() {
    }

    public UrlAuthorizationWebInterceptor(SecurityManager securityManager, String urls) {
        this.securityManager = securityManager;
        this.urls = urls;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    public String getUrls() {
        return urls;
    }

    public void setUrls(String urls) {
        this.urls = urls;
    }

    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        return true;

        //TODO - re-enable this logic.
         /*if( !urlAuthorizationEnabled || urlAuthorizationHandler.isUserAuthorizedForRequest( request ) ) {
            return true;
        } else {
            handleUnauthorizedRequest( request, response );
            return false;
        }*/
    }

    public void postHandle(ServletRequest request, ServletResponse response) throws Exception {
        //no-op
    }

    public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception) throws Exception {
        //no-op
    }

    /**
     * The default implemtation redirects to a configured unauthorized page if one is set.  Otherwise, it simply
     * responds with an HTTP UNAUTHORIZED status code (401).  This method can be overridden by subclasses
     * for different behavior.
     *
     * @param request the current request.
     * @param response the current response.
     * @throws java.io.IOException if there is an error while redirecting.
     */
    protected void handleUnauthorizedRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if( unauthorizedPage != null ) {
            response.sendRedirect( unauthorizedPage );
        } else {
            response.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
        }
    }
}
