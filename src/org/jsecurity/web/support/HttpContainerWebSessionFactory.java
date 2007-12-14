package org.jsecurity.web.support;

import org.jsecurity.session.Session;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.InetAddress;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class HttpContainerWebSessionFactory extends DefaultWebSessionFactory {

    public void init(){}

    protected Session doGetSession( ServletRequest request, ServletResponse response ) {
        Session session = null;

        HttpSession httpSession = ((HttpServletRequest)request).getSession( false );

        if ( httpSession != null ) {
            session = new WebSession(httpSession, SecurityWebSupport.getInetAddress( request ) );
        }

        return session;
    }

    protected Session start( ServletRequest request, ServletResponse response, InetAddress inetAddress ) {
        HttpSession httpSession = ((HttpServletRequest)request).getSession();
        return new WebSession( httpSession, SecurityWebSupport.getInetAddress( request ) );
    }
}
