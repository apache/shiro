package org.jsecurity.web.support;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class SessionWebSupport extends SecurityWebSupport implements Initializable {

    /**
     * Key that may be used for a http request or session attribute to alert that a referencing JSecurity Session
     * has expired.
     */
    public static final String EXPIRED_SESSION_KEY = SessionWebSupport.class.getName() + "_EXPIRED_SESSION_KEY";

    private WebSessionFactory webSessionFactory = null;
    private SessionFactory sessionFactory = null;

    public void setWebSessionFactory( WebSessionFactory webSessionFactory ) {
        this.webSessionFactory = webSessionFactory;
    }

    public WebSessionFactory getWebSessionFactory() {
        return webSessionFactory;
    }

    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public void init() {
        if ( getWebSessionFactory() == null ) {
            WebSessionFactory wsf = createWebSessionFactory();
            if ( wsf == null ) {
                String msg = "createWebSessionFactory implementation must return a non-null WebSessionFactory instance.";
                throw new IllegalStateException( msg );
            }
            setWebSessionFactory( wsf );
        }
    }

    protected WebSessionFactory createWebSessionFactory() {
        SessionFactory sessionFactory = getSessionFactory();
        if ( sessionFactory == null ) {
            String msg = "The SessionFactory property must be set if the WebSessionFactory property is not set.";
            throw new IllegalStateException( msg );
        }
        return new DefaultWebSessionFactory( sessionFactory );
    }

    protected void bindToThread( Session session ) {
        ThreadContext.bind( session );
    }

    protected void unbindSessionFromThread() {
        ThreadContext.unbindSession();
    }

    protected Session acquireSession( HttpServletRequest request, HttpServletResponse response ) {

        Session session;

        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if ( webSessionFactory == null ) {
            String msg = "webSessionFactory property must be set.  This will be automatically created during " +
                "init() if the sessionFactory property is set, or of course, you can inject a " +
                "WebSessionFactory instance directly.";
            throw new IllegalStateException( msg );
        }

        try {
            session = webSessionFactory.getSession( request, response );
            if ( session == null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No JSecurity Session associated with the HttpServletRequest.  " +
                               "Attempting to create a new one." );
                }
                session = webSessionFactory.start( request, response );
                if ( log.isDebugEnabled() ) {
                    log.debug( "Created new JSecurity Session with id [" + session.getSessionId() + "]" );
                }
            } else {
                //update last accessed time:
                session.touch();
            }
        } catch ( InvalidSessionException ise ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Request JSecurity Session is invalid, message: [" + ise.getMessage() + "]." );
            }
            session = handleInvalidSession( request, response, ise );
        }

        return session;
    }

    protected Session handleInvalidSession( HttpServletRequest request,
                                            HttpServletResponse response,
                                            InvalidSessionException ise ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Handling invalid session associated with the request.  Attempting to " +
                       "create a new Session to allow processing to continue" );
        }
        Session session = getWebSessionFactory().start( request, response );

        if ( log.isTraceEnabled() ) {
            log.trace( "Adding EXPIRED_SESSION_KEY as a request attribute to alert that the request's incoming " +
                       "referenced session had expired." );
        }
        request.setAttribute( EXPIRED_SESSION_KEY, Boolean.TRUE );

        return session;
    }

}
