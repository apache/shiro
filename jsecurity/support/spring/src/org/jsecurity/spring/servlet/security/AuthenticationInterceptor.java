package org.jsecurity.spring.servlet.security;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.beans.factory.InitializingBean;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.ri.web.WebUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Simple interceptor that verifies a user is authenticated (logged-in) before allowing a
 * page to be viewd.
 *
 * <p>If the user is not authenticated, they will be forwarded to the login page located
 * at the URL {@link #getLoginURL() getLoginURL()}.  Just prior to being forwarded, the
 * page URL they attempted to view is first saved in the <tt>HttpSession</tt> under the
 * key {@link WebUtils#ATTEMPTED_PAGE_KEY}.
 *
 * <p>Upon a successful login, the login controller may
 * use this session key to foward the user to the page they were attempting to view prior to
 * logging in, a nice usability feature.
 *
 * @author Les Hazlewood
 */
public class AuthenticationInterceptor extends HandlerInterceptorAdapter
    implements InitializingBean {

    protected transient final Log log = LogFactory.getLog( getClass() );

    private String loginURL = null;

    public AuthenticationInterceptor(){}

    public String getLoginURL() {
        return loginURL;
    }

    public void setLoginURL( String loginURL ) {
        this.loginURL = loginURL;
    }

    public void afterPropertiesSet() throws Exception {
        if ( getLoginURL() == null ) {
            String msg = "loginURL property must be set";
            throw new IllegalArgumentException( msg );
        }
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {

        AuthorizationContext authzCtx = SecurityContext.getAuthorizationContext();

        if( authzCtx == null ) {
            StringBuffer attemptedPage = request.getRequestURL();
            String queryString = request.getQueryString();
            if ( queryString != null ) {
                attemptedPage.append( "?" );
                attemptedPage.append( queryString );
            }

            HttpSession httpSession = request.getSession();
            httpSession.setAttribute( WebUtils.ATTEMPTED_PAGE_KEY, attemptedPage.toString() );

            if ( log.isDebugEnabled() ) {
                log.debug( "User is not allowed to access page [" + attemptedPage + "] without " +
                           "first being authenticated.  Forwarding to login page [" +
                           getLoginURL() + "]");
            }

            response.sendRedirect( getLoginURL() );
            return false;

        } else {
            return true;
        }
    }
}
