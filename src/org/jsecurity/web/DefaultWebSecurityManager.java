package org.jsecurity.web;

import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.context.Subject;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.support.DefaultWebRememberMeManager;
import org.jsecurity.web.support.DefaultWebSessionFactory;
import org.jsecurity.web.support.HttpContainerWebSessionFactory;
import org.jsecurity.web.support.SecurityWebSupport;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.Collection;

/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager {

    public static final String HTTP_SESSION_MODE = "http";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    /** The key that is used to store subject principals in the session. */
    public static final String PRINCIPALS_SESSION_KEY =
        DefaultWebSecurityManager.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /** The key that is used to store whether or not the user is authenticated in the session. */
    public static final String AUTHENTICATED_SESSION_KEY =
        DefaultWebSecurityManager.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public DefaultWebSecurityManager() {
        super();
    }

    public DefaultWebSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    public DefaultWebSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    protected void afterSessionFactorySet() {
        setRememberMeManager(new DefaultWebRememberMeManager());
    }

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String sessionMode) {
        this.sessionMode = sessionMode;
    }

    protected boolean isHttpSessionMode() {
        return this.sessionMode.equals(HTTP_SESSION_MODE);
    }

    public void setSessionFactory(SessionFactory sessionFactory) {
        if (!(sessionFactory instanceof WebSessionFactory)) {
            String msg = "The " + getClass().getName() + " implementation requires its underlying SessionFactory " +
                "instance to also implement the " + WebSessionFactory.class.getName() + " interface as well.  " +
                "The SessionFactory instance in question is of type [" + sessionFactory.getClass().getName() + "].";
            throw new IllegalArgumentException(msg);
        }
        super.setSessionFactory(sessionFactory);
    }

    protected SessionFactory createSessionFactory() {
        if (isHttpSessionMode()) {
            return new HttpContainerWebSessionFactory();
        } else {
            DefaultWebSessionFactory dwsf = new DefaultWebSessionFactory();
            dwsf.setCacheProvider(getCacheProvider());
            dwsf.init();
            return dwsf;
        }
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
    public Session getSession(ServletRequest request, ServletResponse response) {
        Session session = ((WebSessionFactory) getSessionFactory()).getSession(request, response);
        if (log.isTraceEnabled()) {
            if (session != null) {
                log.trace("webSessionFactory returned a Session instance of type [" + session.getClass().getName() + "]");
            } else {
                log.trace("webSessionFactory did not return a Session instance.");
            }
        }
        return session;
    }

    protected Object getPrincipals(Session session) {
        Object principals = null;
        if (session != null) {
            principals = session.getAttribute(PRINCIPALS_SESSION_KEY);
        }
        return principals;
    }

    protected Object getPrincipals(Session existing, ServletRequest servletRequest, ServletResponse servletResponse) {
        Object principals = getPrincipals(existing);
        if (principals == null) {
            //check remember me:
            principals = getRememberedIdentity();
            if (principals != null && existing != null) {
                existing.setAttribute(PRINCIPALS_SESSION_KEY, principals);
            }
        }
        return principals;
    }

    protected boolean isAuthenticated(Session session) {
        Boolean value = null;
        if (session != null) {
            value = (Boolean) session.getAttribute(AUTHENTICATED_SESSION_KEY);
        }
        return value != null && value;
    }

    protected boolean isAuthenticated(ServletRequest servletRequest, ServletResponse servletResponse, Session existing) {
        return isAuthenticated(existing);
    }

    public Subject createSubject() {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return createSubject(request, response);
    }

    public Subject createSubject(ServletRequest request, ServletResponse response) {
        Session session = getSession(request, response);
        return createSubject(session, request, response);
    }

    public Subject createSubject(Session existing, ServletRequest request, ServletResponse response) {
        Object principals = getPrincipals(existing, request, response);
        boolean authenticated = isAuthenticated(request, response, existing);
        return createSubject(request, response, existing, principals, authenticated);
    }

    protected Subject createSubject(ServletRequest request,
                                                    ServletResponse response,
                                                    Session existing,
                                                    Object principals,
                                                    boolean authenticated) {
        InetAddress inetAddress = SecurityWebSupport.getInetAddress(request);
        return createSubject(principals, existing, authenticated, inetAddress);
    }

    protected void bind(Subject secCtx) {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        bind(secCtx, request, response);
        super.bind(secCtx);
    }

    protected void bind(Subject subject, ServletRequest request, ServletResponse response) {
        Object principals = subject.getPrincipal();
        if ((principals instanceof Collection) && ((Collection) principals).isEmpty()) {
            principals = null;
        }
        if (principals != null) {
            Session session = subject.getSession();
            session.setAttribute(PRINCIPALS_SESSION_KEY, principals);
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(PRINCIPALS_SESSION_KEY);
            }
        }

        if (subject.isAuthenticated()) {
            Session session = subject.getSession();
            session.setAttribute(AUTHENTICATED_SESSION_KEY, subject.isAuthenticated());
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(AUTHENTICATED_SESSION_KEY);
            }
        }
    }
}
