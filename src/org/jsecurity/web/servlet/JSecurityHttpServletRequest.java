package org.jsecurity.web.servlet;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;

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

    //The following 7 constants support the JSecurity's implementation of the Servlet Specification
    public static final String COOKIE_SESSION_ID_SOURCE = "cookie";
    public static final String URL_SESSION_ID_SOURCE = "url";
    public static final String REFERENCED_SESSION_ID = JSecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID";
    public static final String REFERENCED_SESSION_ID_IS_VALID = JSecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID_VALID";
    public static final String REFERENCED_SESSION_IS_NEW = JSecurityHttpServletRequest.class.getName() + "_REFERENCED_SESSION_IS_NEW";
    public static final String REFERENCED_SESSION_ID_SOURCE = JSecurityHttpServletRequest.class.getName() + "REFERENCED_SESSION_ID_SOURCE";
    public static final String SESSION_ID_NAME = JSecurityHttpSession.DEFAULT_SESSION_ID_NAME;
    /**
     * Key that may be used to alert that the request's  referenced JSecurity Session has expired prior to
     * request processing.
     */
    public static final String EXPIRED_SESSION_KEY = JSecurityHttpServletRequest.class.getName() + "_EXPIRED_SESSION_KEY";

    protected ServletContext servletContext = null;

    protected HttpSession session = null;

    protected boolean useJSecuritySessions = true;

    public JSecurityHttpServletRequest( HttpServletRequest wrapped, ServletContext servletContext,
                                        boolean useJSecuritySessions ) {
        super( wrapped );
        this.servletContext = servletContext;
        this.useJSecuritySessions = useJSecuritySessions;
    }

    public boolean isUseJSecuritySessions() {
        return useJSecuritySessions;
    }

    public String getRemoteUser() {
        String remoteUser = null;
        Object scPrincipal = getSecurityContextPrincipal();
        if ( scPrincipal != null ) {
            if ( scPrincipal instanceof Principal ) {
                remoteUser = ( (Principal)scPrincipal ).getName();
            } else {
                remoteUser = scPrincipal.toString();
            }
        } else {
            remoteUser = super.getRemoteUser();
        }
        return remoteUser;
    }

    protected SecurityContext getSecurityContext() {
        return ThreadContext.getSecurityContext();
    }

    protected Object getSecurityContextPrincipal() {
        Object userPrincipal = null;
        SecurityContext sc = getSecurityContext();
        if ( sc != null ) {
            userPrincipal = sc.getPrincipal();
        }
        return userPrincipal;
    }

    public boolean isUserInRole( String s ) {
        SecurityContext sc = getSecurityContext();
        boolean inRole = ( sc != null && sc.hasRole( s ) );
        if ( !inRole ) {
            inRole = super.isUserInRole( s );
        }
        return inRole;
    }

    public Principal getUserPrincipal() {
        Principal userPrincipal = null;
        Object scPrincipal = getSecurityContextPrincipal();
        if ( scPrincipal != null ) {
            if ( scPrincipal instanceof Principal ) {
                userPrincipal = (Principal)scPrincipal;
            } else {
                userPrincipal = new ObjectPrincipal( scPrincipal );
            }
        } else {
            userPrincipal = super.getUserPrincipal();
        }
        return userPrincipal;
    }

    public String getRequestedSessionId() {
        String requestedSessionId = null;

        if ( isUseJSecuritySessions() ) {
            Object sessionId = getAttribute( REFERENCED_SESSION_ID );
            if ( sessionId != null ) {
                requestedSessionId = sessionId.toString();
            }
        } else {
            requestedSessionId = super.getRequestedSessionId();
        }

        return requestedSessionId;
    }

    public HttpSession getSession( boolean create ) {

        HttpSession httpSession = null;

        if ( isUseJSecuritySessions() ) {

            if ( this.session == null ) {

                boolean existing = getSecurityContext().getSession( false ) != null;

                Session jsecSession = getSecurityContext().getSession( create );
                if ( jsecSession != null ) {
                    this.session = new JSecurityHttpSession( jsecSession, this, this.servletContext );
                    if ( !existing ) {
                        setAttribute( REFERENCED_SESSION_IS_NEW, Boolean.TRUE );
                    }
                }
            }
            httpSession = this.session;
        } else {
            httpSession = super.getSession( create );
        }

        return httpSession;
    }


    public HttpSession getSession() {
        return getSession( true );
    }

    public boolean isRequestedSessionIdValid() {
        if ( isUseJSecuritySessions() ) {
            Boolean value = (Boolean)getAttribute( REFERENCED_SESSION_ID_IS_VALID );
            return ( value != null && value.equals( Boolean.TRUE ) );
        } else {
            return super.isRequestedSessionIdValid();
        }
    }

    public boolean isRequestedSessionIdFromCookie() {
        if ( isUseJSecuritySessions() ) {
            String value = (String)getAttribute( REFERENCED_SESSION_ID_SOURCE );
            return value != null && value.equals( COOKIE_SESSION_ID_SOURCE );
        } else {
            return super.isRequestedSessionIdFromCookie();
        }
    }

    public boolean isRequestedSessionIdFromURL() {
        if ( isUseJSecuritySessions() ) {
            String value = (String)getAttribute( REFERENCED_SESSION_ID_SOURCE );
            return value != null && value.equals( URL_SESSION_ID_SOURCE );
        } else {
            return super.isRequestedSessionIdFromURL();
        }
    }

    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    private class ObjectPrincipal implements java.security.Principal {
        private Object object = null;

        public ObjectPrincipal( Object object ) {
            this.object = object;
        }

        public Object getObject() {
            return object;
        }

        public String getName() {
            return getObject().toString();
        }

        public int hashCode() {
            return object.hashCode();
        }

        public boolean equals( Object o ) {
            if ( o instanceof ObjectPrincipal ) {
                ObjectPrincipal op = (ObjectPrincipal)o;
                return getObject().equals( op.getObject() );
            }
            return false;
        }

        public String toString() {
            return object.toString();
        }
    }
}
