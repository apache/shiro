package org.jsecurity.web.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
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

    protected WebSessionFactory webSessionFactory = null;

    private boolean preferHttpSessionStorage = false;

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

    public boolean isPreferHttpSessionStorage() {
        return preferHttpSessionStorage;
    }

    public void setPreferHttpSessionStorage( boolean preferHttpSessionStorage ) {
        this.preferHttpSessionStorage = preferHttpSessionStorage;
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
            DefaultWebSessionFactory dwsf = new DefaultWebSessionFactory( securityManager );
            setWebSessionFactory( dwsf );
        }
    }

    public void init() {
        assertSecurityManager();
        if ( !isPreferHttpSessionStorage() ) {
            ensureWebSessionFactory();
        }
    }

    protected List getPrincipals( ServletRequest servletRequest ) {
        List principals = null;

        HttpSession httpSession = toHttp( servletRequest ).getSession( false );
        if ( httpSession != null ) {
            principals = (List)httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
        }

        return principals;
    }

    protected List getPrincipals( ServletRequest servletRequest, ServletResponse servletResponse ) {
        return getPrincipals( servletRequest );
    }

    protected boolean isAuthenticated( ServletRequest servletRequest ) {
        Boolean value = null;

        HttpSession httpSession = toHttp( servletRequest ).getSession( false );
        if ( httpSession != null ) {
            value = (Boolean)httpSession.getAttribute( AUTHENTICATED_SESSION_KEY );
        }

        return value != null && value;
    }

    protected boolean isAuthenticated( ServletRequest servletRequest, ServletResponse servletResponse ) {
        return isAuthenticated( servletRequest );
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
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return the raw {@link Session session} associated with the request, or <tt>null</tt> if there isn't one.
     */
    protected Session getSession( ServletRequest request, ServletResponse response ) {

        if ( !isPreferHttpSessionStorage() ) {
            WebSessionFactory webSessionFactory = getWebSessionFactory();

            if ( webSessionFactory == null ) {
                String msg = "webSessionFactory property must be set when using JSecurity sessions.  This is done by " +
                    "default during the init() method.  Please ensure init() is called before using this instance.";
                throw new IllegalStateException( msg );
            }

            return webSessionFactory.getSession( request, response );
        } else {
            return null;
        }
    }

    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response ) {

        //if there is a raw JSecurity Session already associated with the request, ensure it is passed along to the 
        //underlying SecurityContext so it can be used (instead of the SecurityContext implementation creating a brand
        //new one the first time it is requested):

        Session session = getSession( request, response );

        SecurityContext sc = null;

        try {
            //Create a dummy context with the acquired session and bind it to the thread.  The next method call uses
            //code that expects an SC to be bound to the thread.
            sc = createSecurityContext( request, response, null, false, session );
            ThreadContext.bind( sc );

            //this is the call the requires a thread-bound SC:
            sc = createSecurityContext( request, response, session );
        } finally {
            //remove the dummy in any case:
            ThreadContext.unbindSecurityContext();
        }

        return sc;
    }

}
