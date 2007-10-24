package org.jsecurity.web.servlet;

import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.web.support.DefaultWebSessionFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;
import java.security.Principal;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class JSecurityHttpServletRequest extends HttpServletRequestWrapper {

    protected ServletContext servletContext = null;
    protected SecurityManager securityManager = null;
    protected WebSessionFactory webSessionFactory = null;

    protected HttpSession session = null;

    public JSecurityHttpServletRequest( HttpServletRequest wrapped, ServletContext servletContext,
                                        SecurityManager securityManager, WebSessionFactory webSessionFactory ) {
        super( wrapped );
        this.servletContext = servletContext;
        this.securityManager = securityManager;
        this.webSessionFactory = webSessionFactory;
    }

    public String getRemoteUser() {
        String remoteUser = null;
        SecurityContext sc = getSecurityContext();
        if ( sc != null ) {
            Object userPrincipal = sc.getPrincipal();
            if ( userPrincipal != null ) {
                remoteUser = userPrincipal.toString();
            }
        }
        return remoteUser;
    }

    protected SecurityContext getSecurityContext() {
        return ThreadContext.getSecurityContext();
    }

    public boolean isUserInRole( String s ) {
        SecurityContext sc = getSecurityContext();
        return ( sc != null && sc.hasRole( s ) );
    }

    public Principal getUserPrincipal() {
        Principal principal = null;
        String remoteUser = getRemoteUser();
        if ( remoteUser != null ) {
            principal = new StringPrincipal( remoteUser );
        }
        return principal;
    }

    public String getRequestedSessionId() {
        return (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID );
    }

    public HttpSession getSession( boolean create ) {
        if ( this.session == null ) {
            Session jsecSession = webSessionFactory.getSession( this, null );
            if ( jsecSession == null && create ) {
                jsecSession = webSessionFactory.start( this, null );
            }
            ThreadContext.bind( jsecSession );

            SecurityContext existing = getSecurityContext();
            DelegatingSecurityContext dsc = null;
            if ( existing != null ) {
                dsc = new DelegatingSecurityContext( existing.getAllPrincipals(), existing.isAuthenticated(),
                    ThreadContext.getInetAddress(), jsecSession, this.securityManager );
            } else {
                dsc = new DelegatingSecurityContext( false, ThreadContext.getInetAddress(),
                    jsecSession, this.securityManager );

            }
            ThreadContext.bind( dsc );

            this.session = new JSecurityHttpSession( this.servletContext );

        }
        return this.session;
    }

    public HttpSession getSession() {
        return getSession( true );
    }

    public boolean isRequestedSessionIdValid() {
        Boolean value = (Boolean)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_IS_VALID );
        return ( value != null && value.equals( Boolean.TRUE ) );
    }

    public boolean isRequestedSessionIdFromCookie() {
        String value = (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_SOURCE );
        return value != null && value.equals( DefaultWebSessionFactory.COOKIE_ID_SOURCE );
    }

    public boolean isRequestedSessionIdFromURL() {
        String value = (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_SOURCE );
        return value != null && value.equals( DefaultWebSessionFactory.URL_ID_SOURCE );

    }

    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    private class StringPrincipal implements java.security.Principal {
        private String name = null;

        public StringPrincipal( String name ) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public int hashCode() {
            return name.hashCode();
        }

        public boolean equals( Object o ) {
            return name.equals( o );
        }

        public String toString() {
            return name;
        }
    }
}
