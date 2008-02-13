package org.jsecurity.web.support;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class HttpContainerWebSessionFactory implements SessionFactory, WebSessionFactory {

    public HttpContainerWebSessionFactory(){}

    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return start(request, response, hostAddress);
    }

    public Session start(ServletRequest request, ServletResponse response) {
        InetAddress hostAddress = SecurityWebSupport.getInetAddress(request);
        return start(request, response, hostAddress);
    }

    protected Session start(ServletRequest request, ServletResponse response, InetAddress inetAddress) {
        HttpSession httpSession = ((HttpServletRequest) request).getSession();
        if ( inetAddress == null ) {
            inetAddress = SecurityWebSupport.getInetAddress( request );
        }
        return new WebSession(httpSession, inetAddress);
    }

    public Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        //Session argument is ignored since the HTTP container manages sessions.
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return getSession(request, response);
    }


    public Session getSession(ServletRequest request, ServletResponse response) throws AuthorizationException {
        Session session = null;
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        if (httpSession != null) {
            session = new WebSession(httpSession, SecurityWebSupport.getInetAddress(request));
        }
        return session;
    }


}
