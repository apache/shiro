package org.jsecurity.web.session;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.mgt.AbstractSessionManager;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * SessionManager implementation providing Session implementations that are merely wrappers for the
 * Servlet container's HttpSession.
 *
 * <p>Despite its name, this implementation <em>does not</em> itself manage Sessions since the Servlet container
 * provides the actual management support.  This class mainly exists to 'impersonate' a regular JSecurity
 * <tt>SessionManager</tt> so it can be pluggable into a normal JSecurity configuration in a pure web application.
 *
 * <p>Note that because this implementation relies on the <tt>HttpSession</tt>, it is only functional in a servlet
 * container.  I.e. it is <em>NOT</em> capable of supporting Sessions any clients other than HttpRequest/HttpResponse
 * based clients.
 *
 * <p>Therefore, if you need heterogenous Session support across multiple client mediums (e.g. web pages,
 * Flash applets, Java Web Start applications, etc.), use the {@link WebSessionManager WebSessionManager} instead.  The
 * <tt>WebSessionManager</tt> supports both traditional web-based access as well as non web-based clients.
 *
 * @author Les Hazlewood
 * @since 0.9
 *
 */
public class ServletContainerSessionManager extends AbstractSessionManager {

    protected Session doGetSession(Serializable sessionId) throws InvalidSessionException {
        //Ignore session id since there is no way to acquire a session based on an id in a servlet container
        //(that is implementation agnostic)
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return doGetSession( request, response );
    }

    public Session doGetSession(ServletRequest request, ServletResponse response) throws AuthorizationException {
        Session session = null;
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        if (httpSession != null) {
            session = createSession( httpSession, SecurityWebSupport.getInetAddress(request) );
        }
        return session;
    }

    protected Session createSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        ServletRequest request = ThreadContext.getServletRequest();
        HttpSession httpSession = ((HttpServletRequest)request).getSession();
        return createSession( httpSession, originatingHost );
    }

    protected Session createSession( HttpSession httpSession, InetAddress inet ) {
        return new WebSession( httpSession, inet );
    }

}
