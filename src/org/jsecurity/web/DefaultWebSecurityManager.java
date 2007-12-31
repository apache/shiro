package org.jsecurity.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.util.LifecycleUtils;
import org.jsecurity.web.support.DefaultWebSessionFactory;
import org.jsecurity.web.support.HttpContainerWebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {

    public static final String HTTP_SESSION_MODE = "web";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    protected transient final Log log = LogFactory.getLog(getClass());

    /**
     * The DefaultWebSecurityManager does not implment the WebSessionFactory interface directly - instead it
     * delegates these calls to the following wrapped instance:
     */
    protected WebSessionFactory webSessionFactory = null;
    private boolean webSessionFactoryImplicitlyCreated = false;

    private String sessionMode = HTTP_SESSION_MODE; //default

    public WebSessionFactory getWebSessionFactory() {
        return webSessionFactory;
    }

    public void setWebSessionFactory(WebSessionFactory webSessionFactory) {
        this.webSessionFactory = webSessionFactory;
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

    private WebSessionFactory createWebSessionFactory() {

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

    protected void ensureWebSessionFactory() {
        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if (webSessionFactory == null) {
            webSessionFactory = createWebSessionFactory();
            if (webSessionFactory == null) {
                String msg = "webSessionFactory instance returned from createWebSessionFactory() call cannot be null.";
                throw new IllegalStateException(msg);
            }
            this.webSessionFactory = webSessionFactory;
            this.webSessionFactoryImplicitlyCreated = true;
        }
    }

    protected void ensureSessionFactory() {
        SessionFactory sessionFactory = getSessionFactory();
        if (sessionFactory == null) {
            if (!(this.webSessionFactory instanceof SessionFactory)) {
                String msg = "The " + getClass().getName() + " class requires its delegate " +
                        "WebSessionFactory instance to also implement the " +
                        SessionFactory.class.getName() + " interface when a sessionFactory instance " +
                        "is not set as an attribute.";
                throw new IllegalStateException(msg);
            }
            setSessionFactory((SessionFactory) this.webSessionFactory);
        }
    }

    public void init() {
        ensureCacheProvider();
        ensureRealms();
        ensureAuthenticator();
        ensureAuthorizer();
        ensureWebSessionFactory();
        ensureSessionFactory();
    }

    public void destroy() {
        if ( webSessionFactoryImplicitlyCreated ) {
            LifecycleUtils.destroy( webSessionFactory );
            webSessionFactory = null;
            webSessionFactoryImplicitlyCreated = false;
        }
        super.destroy();
    }

    public Session start(ServletRequest request, ServletResponse response) {
        return this.webSessionFactory.start(request, response);
    }

    public Session getSession(ServletRequest request, ServletResponse response) throws InvalidSessionException, AuthorizationException {
        return webSessionFactory.getSession(request, response);
    }
}
