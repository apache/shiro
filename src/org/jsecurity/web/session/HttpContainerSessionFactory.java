package org.jsecurity.web.session;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.Session;
import org.jsecurity.web.SecurityWebSupport;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.InetAddress;

/**
 * Returns <tt>Session</tt> instances that are merely wrappers for the Http container's HttpSession.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class HttpContainerSessionFactory extends WebSessionFactory {

    public HttpContainerSessionFactory(){}

    protected Session createSession( HttpSession httpSession, InetAddress inet ) {
        return new WebSession( httpSession, inet );
    }

    protected Session start(ServletRequest request, ServletResponse response, InetAddress inetAddress) {
        HttpSession httpSession = ((HttpServletRequest) request).getSession();
        return createSession( httpSession, inetAddress );
    }

    public Session doGetSession(ServletRequest request, ServletResponse response) throws AuthorizationException {
        Session session = null;
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        if (httpSession != null) {
            session = createSession( httpSession, SecurityWebSupport.getInetAddress(request) );
        }
        return session;
    }
}
