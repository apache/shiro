package org.jsecurity.web.servlet;

import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.servlet.authz.DefaultUrlAuthorizationHelper;
import org.jsecurity.web.servlet.authz.UrlAuthorizationHandler;
import org.jsecurity.web.support.SecurityWebSupport;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since Feb 4, 2008 7:38:44 PM
 */
public class JSecurityFilter extends SecurityManagerFilter {

    protected String unauthorizedPage;

    protected UrlAuthorizationHandler urlAuthorizationHandler;
    protected boolean urlAuthorizationEnabled = false;

    public UrlAuthorizationHandler getUrlAuthorizationHandler() {
        if( urlAuthorizationHandler == null ) {
            urlAuthorizationHandler = new DefaultUrlAuthorizationHelper();
        }
        return urlAuthorizationHandler;
    }

    public void setUrlAuthorizationHandler(UrlAuthorizationHandler urlAuthorizationHandler) {
        this.urlAuthorizationHandler = urlAuthorizationHandler;
    }

    protected void afterSecurityManagerSet() throws Exception {
        FilterConfig config = getFilterConfig();
        this.unauthorizedPage = config.getInitParameter( "unauthorizedPage" );
        this.urlAuthorizationEnabled = getUrlAuthorizationHandler().configureUrlAuthorization( getSecurityManager(), config );
    }


    protected void doFilterInternal(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        ThreadContext.bind( SecurityWebSupport.getInetAddress( request ) );

        boolean httpSessions = isHttpSessions();
        request = new JSecurityHttpServletRequest( request, getServletContext(), httpSessions );
        if ( !httpSessions ) {
            //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
            //using JSecurity sessions (i.e. not simple HttpSession based sessions):
            response = new JSecurityHttpServletResponse( response, getServletContext(), (JSecurityHttpServletRequest)request );
        }

        ThreadContext.bind( request );
        ThreadContext.bind( response );
        ThreadContext.bind( getSecurityManager().getSubject() );

        try {

            if( !urlAuthorizationEnabled || urlAuthorizationHandler.isUserAuthorizedForRequest( request ) ) {
                chain.doFilter( request, response );
            } else {
                handleUnauthorizedRequest( request, response );
            }

        } finally {
            ThreadContext.unbindServletRequest();
            ThreadContext.unbindServletResponse();
            ThreadContext.unbindInetAddress();
            ThreadContext.unbindSubject();
        }
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
