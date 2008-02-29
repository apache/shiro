package org.jsecurity.web.support;

import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.Collection;

/**
 * SecurityManager implementation that should be used in web-based applications or any application that requires
 * HTTP connectivity (SOAP, http remoting, etc).
 * 
 * @author Les Hazlewood
 * @since 0.2
 */
public class WebSecurityManager extends DefaultSecurityManager {

    public static final String HTTP_SESSION_MODE = "http";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    /** The key that is used to store subject principals in the session. */
    public static final String PRINCIPALS_SESSION_KEY = WebSecurityManager.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /** The key that is used to store whether or not the user is authenticated in the session. */
    public static final String AUTHENTICATED_SESSION_KEY = WebSecurityManager.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public WebSecurityManager() {
        super();
    }

    public WebSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    public WebSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    protected void afterSessionFactorySet() {
        WebRememberMeManager rmm = new WebRememberMeManager();
        rmm.init();
        setRememberMeManager(rmm);
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

    protected SessionFactory createSessionFactory() {
        if (isHttpSessionMode()) {
            return new HttpContainerSessionFactory();
        } else {
            WebSessionFactory wsf = new WebSessionFactory();
            wsf.setCacheProvider(getCacheProvider());
            wsf.init();
            return wsf;
        }
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
        Session session = getSession(null); //expected the underlying SessionFactory can pull from the thread-local request
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

    protected void bind(Subject subject) {
        super.bind(subject);
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        bind(subject, request, response);
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
