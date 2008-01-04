package org.jsecurity.web;

import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.web.support.DefaultWebSessionFactory;
import org.jsecurity.web.support.HttpContainerWebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {

    public static final String HTTP_SESSION_MODE = "http";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String sessionMode) {
        this.sessionMode = sessionMode;
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        if ( !(sessionFactory instanceof WebSessionFactory ) ) {
            String msg = "The " + getClass().getName() + " implementation requires its underlying SessionFactory " +
                    "instance to also implement the " + WebSessionFactory.class.getName() + " interface as well.  " +
                    "The SessionFactory instance in question is of type [" + sessionFactory.getClass().getName() + "].";
            throw new IllegalArgumentException( msg );
        }
        super.setSessionFactory(sessionFactory);
    }

    protected boolean isHttpSessionMode() {
        return this.sessionMode.equals(HTTP_SESSION_MODE);
    }

    protected SessionFactory createSessionFactory() {
        DefaultWebSessionFactory webSessionFactory;

        if (isHttpSessionMode()) {
            webSessionFactory = new HttpContainerWebSessionFactory();
        } else {
            webSessionFactory = new DefaultWebSessionFactory();
        }

        webSessionFactory.setCacheProvider( getCacheProvider() );

        webSessionFactory.init();

        return webSessionFactory;
    }

    public Session start(ServletRequest request, ServletResponse response) {
        return ((WebSessionFactory)getSessionFactory()).start(request, response);
    }

    public Session getSession(ServletRequest request, ServletResponse response) throws InvalidSessionException, AuthorizationException {
        return ((WebSessionFactory)getSessionFactory()).getSession(request, response);
    }
}
