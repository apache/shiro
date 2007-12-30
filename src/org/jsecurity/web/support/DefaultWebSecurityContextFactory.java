package org.jsecurity.web.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactoryAware;
import org.jsecurity.web.WebSecurityContextFactory;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
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

    protected void assertSecurityManager() {
        if ( getSecurityManager() == null ) {
            String msg = "SecurityManager property must be set.";
            throw new IllegalStateException( msg );
        }
    }

    protected void assertWebSessionFactory() {
        if ( getWebSessionFactory() == null ) {

            SecurityManager securityManager = getSecurityManager();

            if ( securityManager instanceof SessionFactoryAware) {
                Object sf = ((SessionFactoryAware)securityManager).getSessionFactory();
                if ( !(sf instanceof WebSessionFactory ) ) {
                    String msg = "The SessionFactory returned from SecurityManager.getSessionFactory() does " +
                        "not implement the " + WebSessionFactory.class.getName() + " interface.  This is " +
                        "required when running JSecurity in web environments.";
                    throw new IllegalStateException( msg );
                }
                setWebSessionFactory( (WebSessionFactory)sf );
            } else {
                String msg = "WebSessionFactory property is not set.  Because the SecurityManager does not " +
                    "implement the " + SessionFactoryAware.class.getName() + " interface, JSecurity cannot try to " +
                    "acquire the SessionFactory from the SecurityManager.";
                throw new IllegalStateException( msg );
            }
        } else {
            throw new IllegalStateException( "WebSessionFactory property must be set." );
        }
    }

    public void init() {
        assertSecurityManager();
        assertWebSessionFactory();
    }

    protected List getPrincipals( Session session ) {
        List principals = null;

        if ( session != null ) {
            principals = (List)session.getAttribute( PRINCIPALS_SESSION_KEY );
        }

        return principals;
    }

    protected List getPrincipals( ServletRequest servletRequest, ServletResponse servletResponse, Session existing ) {
        return getPrincipals( existing );
    }

    protected boolean isAuthenticated( Session session ) {
        Boolean value = null;

        if ( session != null ) {
            value = (Boolean)session.getAttribute( AUTHENTICATED_SESSION_KEY );
        }

        return value != null && value;
    }

    protected boolean isAuthenticated( ServletRequest servletRequest, ServletResponse servletResponse, Session existing ) {
        return isAuthenticated( existing );
    }
    
    protected SecurityContext createSecurityContext( ServletRequest request,
                                                     ServletResponse response,
                                                     List principals,
                                                     boolean authenticated,
                                                     Session existing ) {
        SecurityManager securityManager = getSecurityManager();

        if ( securityManager == null ) {
            final String message = "the SecurityManager attribute must be configured.  This could be " +
                "done by calling setSecurityManager() on the " + getClass().getName() + " instance, or by subclassing " +
                "to retrieve the SecurityManager from an application framework.";
            throw new IllegalStateException( message );
        }

        InetAddress inetAddress = getInetAddress( request );

        return new DelegatingSecurityContext( principals, authenticated, inetAddress, existing, securityManager );
    }

    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response, Session existing ) {
        List principals = getPrincipals( request, response, existing );
        boolean authenticated = isAuthenticated( request, response, existing );
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
        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if ( webSessionFactory == null ) {
            String msg = "The webSessionFactory property must be set.  This is done by " +
                       "default during the init() method.  Please ensure init() is called before using this instance.";
            throw new IllegalStateException( msg );
        }
        Session session = webSessionFactory.getSession( request, response );
        if ( log.isTraceEnabled() ) {
            if ( session != null ) {
                log.trace( "webSessionFactory returned a Session instance of type [" + session.getClass().getName() + "]");
            } else {
                log.trace( "webSessionFactory did not return a Session instance." );
            }
        }
        return session;
    }

    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response ) {
        Session session = getSession( request, response );
        return createSecurityContext( request, response, session );
    }

    protected void bindForSubsequentRequests( ServletRequest request, ServletResponse response, SecurityContext securityContext ) {
        List allPrincipals = securityContext.getAllPrincipals();
        if ( allPrincipals != null && !allPrincipals.isEmpty() ) {
            Session session = securityContext.getSession();
            session.setAttribute( PRINCIPALS_SESSION_KEY, allPrincipals );
            if ( securityContext.isAuthenticated() ) {
                session.setAttribute( AUTHENTICATED_SESSION_KEY, securityContext.isAuthenticated() );
            } else {
                session.removeAttribute( AUTHENTICATED_SESSION_KEY );
            }
        }
    }

}
