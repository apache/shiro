package org.jsecurity.web.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionManager;
import org.jsecurity.web.WebSecurityContextFactory;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import java.net.InetAddress;
import java.util.List;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class DefaultWebSecurityContextFactory extends SecurityWebSupport implements WebSecurityContextFactory {

    /**
     * The key that is used to store subject principals in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY =
        DefaultWebSecurityContextFactory.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The key that is used to store whether or not the user is authenticated in the session.
     */
    public static final String AUTHENTICATED_SESSION_KEY =
        DefaultWebSecurityContextFactory.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    protected SecurityManager securityManager = null;
    protected SessionManager sessionManager = null;

    protected WebSessionFactory webSessionFactory = null;

    public DefaultWebSecurityContextFactory() {
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    public WebSessionFactory getWebSessionFactory() {
        return webSessionFactory;
    }

    public void setWebSessionFactory( WebSessionFactory webSessionFactory ) {
        this.webSessionFactory = webSessionFactory;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public void setSessionManager( SessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    void assertSecurityManager() {
        SecurityManager securityManager = getSecurityManager();
        if ( securityManager == null ) {
            String msg = "SecurityManager property must be set.";
            throw new IllegalStateException( msg );
        }
    }


    void ensureWebSessionFactory() {
        if ( getWebSessionFactory() == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Initializing default WebSessionFactory instance..." );
            }

            SecurityManager securityManager = getSecurityManager();
            SessionManager sessionManager = getSessionManager();
            if ( sessionManager == null ) {
                if ( securityManager instanceof SessionManager ) {
                    sessionManager = (SessionManager)securityManager;
                } else {
                    String msg = getClass().getName() + " class requires the SessionManager property to be set if " +
                        "the WebSessionFactory property is not set.";
                    throw new IllegalStateException( msg );
                }
            }

            DefaultWebSessionFactory dwsf = new DefaultWebSessionFactory( sessionManager );
            setWebSessionFactory( dwsf );
        }
    }

    public void init() {
        assertSecurityManager();
        ensureWebSessionFactory();
    }

    protected List getPrincipals( ServletRequest servletRequest, ServletResponse servletResponse ) {

        List principals = null;

        HttpSession httpSession = toHttp(servletRequest).getSession( false );
        if ( httpSession != null ) {
            principals = (List)httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
        }

        return principals;
    }

    protected boolean isAuthenticated( ServletRequest servletRequest, ServletResponse servletResponse ) {
        Boolean value = null;

        HttpSession httpSession = toHttp(servletRequest).getSession( false );
        if ( httpSession != null ) {
            value = (Boolean)httpSession.getAttribute( AUTHENTICATED_SESSION_KEY );
        }

        return value != null && value;
    }

    protected SecurityContext createSecurityContext( List principals, boolean authenticated,
                                                     InetAddress inetAddress, Session session,
                                                     SecurityManager securityManager ) {
        return new DelegatingSecurityContext( principals, authenticated, inetAddress, session, securityManager );
    }

    protected SecurityContext createSecurityContext( ServletRequest request,
                                                     ServletResponse response,
                                                     List principals,
                                                     boolean authenticated,
                                                     Session existing ) {
        SecurityContext securityContext;

        SecurityManager securityManager = getSecurityManager();

        if ( securityManager == null ) {
            final String message = "the SecurityManager attribute must be configured.  This could be " +
                "done by calling setSecurityManager() on the " + getClass().getName() + " instance, or by subclassing " +
                "to retrieve the SecurityManager from an application framework.";
            throw new IllegalStateException( message );
        }

        
        InetAddress inetAddress = getInetAddress( request );

        securityContext = createSecurityContext( principals, authenticated, inetAddress, existing, securityManager );

        return securityContext;
    }

    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response, Session existing ) {
        List principals = getPrincipals( request, response );
        boolean authenticated = isAuthenticated( request, response );
        return createSecurityContext( request, response, principals, authenticated, existing );
    }

    /**
     * Returns the raw {@link Session session} associated with the request, or <tt>null</tt> if there isn't one.
     *
     * <p>Implementation note: this implementation merely delegates to an internal <tt>WebSessionFactory</tt> to perform
     * the lookup.
     *
     * @param request incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return the raw {@link Session session} associated with the request, or <tt>null</tt> if there isn't one.
     */
    protected Session getSession( ServletRequest request, ServletResponse response ) {

        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if ( webSessionFactory == null ) {
            String msg = "webSessionFactory property must be set.  This is done by default during the init() " +
                "method.  Please ensure init() is called before using this instance.";
            throw new IllegalStateException( msg );
        }

        return webSessionFactory.getSession( request, response );
    }

    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response ) {

        //if there is a raw JSecurity Session already associated with the request, ensure it is passed along to the 
        //underlying SecurityContext so it can be used (instead of the SecurityContext implementation creating a brand
        //new one the first time it is requested):

        Session session = getSession( request, response );

        return createSecurityContext( request, response, session );
    }

}
