package org.jsecurity.web.servlet;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.support.DefaultWebSessionFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.Enumeration;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class JSecurityHttpServletRequest extends JSecurityServletRequest implements HttpServletRequest {

    protected HttpServletRequest wrapped = null;
    protected ServletContext servletContext = null;

    public JSecurityHttpServletRequest( HttpServletRequest wrapped, ServletContext servletContext ) {
        super( wrapped );   
        this.wrapped = wrapped;
        this.servletContext = servletContext;
    }

    public String getAuthType() {
        return wrapped.getAuthType();
    }

    public Cookie[] getCookies() {
        return wrapped.getCookies();
    }

    public long getDateHeader( String s ) {
        return wrapped.getDateHeader(s);
    }

    public String getHeader( String s ) {
        return wrapped.getHeader( s );
    }

    public Enumeration getHeaders( String s ) {
        return wrapped.getHeaders( s );
    }

    public Enumeration getHeaderNames() {
        return wrapped.getHeaderNames();
    }

    public int getIntHeader( String s ) {
        return wrapped.getIntHeader( s );
    }

    public String getMethod() {
        return wrapped.getMethod();
    }

    public String getPathInfo() {
        return wrapped.getPathInfo();
    }

    public String getPathTranslated() {
        return wrapped.getPathTranslated();
    }

    public String getContextPath() {
        return wrapped.getContextPath();
    }

    public String getQueryString() {
        return wrapped.getQueryString();
    }

    public String getRemoteUser() {

        return wrapped.getRemoteUser();
    }

    protected SecurityContext getSecurityContext() {
        return ThreadContext.getSecurityContext();
    }

    public boolean isUserInRole( String s ) {
        SecurityContext sc = getSecurityContext();
        return ( sc != null && sc.hasRole( s ) );
    }

    public Principal getUserPrincipal() {
        SecurityContext sc = getSecurityContext();
        Principal principal = null;
        if ( sc != null ) {
            Object userPrincipal = sc.getPrincipal();
            if ( userPrincipal != null ) {
                principal = new StringPrincipal( userPrincipal.toString() );
            }
        }
        return principal;
    }

    public String getRequestedSessionId() {
        return (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_THREAD_CONTEXT_KEY );
    }

    public String getRequestURI() {
        return wrapped.getRequestURI();
    }

    public StringBuffer getRequestURL() {
        return wrapped.getRequestURL();
    }

    public String getServletPath() {
        return wrapped.getServletPath();
    }

    public HttpSession getSession( boolean b ) {
        if ( b ) {
            return getSession();
        }
        return null;
    }

    public HttpSession getSession() {
        SecurityContext sc = getSecurityContext();
        if ( sc != null ) {
            JSecurityHttpSession jsecSession = new JSecurityHttpSession( this.servletContext );
            //force JSecurity session creation:
            jsecSession.getId();
            return jsecSession;
        }
        return null;
    }

    public boolean isRequestedSessionIdValid() {
        Boolean value = (Boolean)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_VALID_THREAD_CONTEXT_KEY );
        return ( value != null && value.equals( Boolean.TRUE ) );
    }

    public boolean isRequestedSessionIdFromCookie() {
        String value = (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_SOURCE_THREAD_CONTEXT_KEY );
        return value != null && value.equals( DefaultWebSessionFactory.COOKIE_ID_SOURCE );
    }

    public boolean isRequestedSessionIdFromURL() {
        String value = (String)ThreadContext.get( DefaultWebSessionFactory.REQUEST_REFERENCED_SESSION_ID_SOURCE_THREAD_CONTEXT_KEY );
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
