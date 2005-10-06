package org.jsecurity.spring.servlet.security;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.util.ThreadContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Associates an HttpServletRequest with an existing {@link Session Session}, if one can be found
 * for association based on the request.  If a <tt>Session</tt> cannot be found, this interceptor
 * creates a new one.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SessionInterceptor extends HandlerInterceptorAdapter {

    private static final String SESSION_THREAD_CONTEXT_KEY =
        Session.class.getName() + "_THREAD_CONTEXT_KEY";

    protected transient final Log log = LogFactory.getLog( getClass() );

    private WebSessionFactory webSessionFactory = null;

    public void setWebSessionFactory( WebSessionFactory webSessionFactory ) {
        this.webSessionFactory = webSessionFactory;
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response,
                              Object handler ) throws Exception {

        boolean continueProcessing = true;

        try {
            Session session = webSessionFactory.getSession( request );
            if ( session == null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No JSecurity Session associated with the HttpServletRequest.  " +
                               "Attempting to create a new one." );
                }
                session = webSessionFactory.start( request );
                if ( log.isDebugEnabled() ) {
                    log.debug( "Created new JSecurity Session with id [" +
                               session.getSessionId() + "]");
                }
            }

            bind( session );

        } catch ( InvalidSessionException ise ) {
            continueProcessing = handleInvalidSession( request, response, handler );
        }

        return continueProcessing;
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response,
                                 Object handler, Exception ex ) throws Exception {
        unbindSession();
    }

    protected void bind( Session session ) {
        if ( session != null ) {
            ThreadContext.put( SESSION_THREAD_CONTEXT_KEY, session );
        }
    }

    protected void unbindSession() {
        ThreadContext.remove( SESSION_THREAD_CONTEXT_KEY );
    }

    protected boolean handleInvalidSession( HttpServletRequest request,
                                            HttpServletResponse response,
                                            Object handler ) {
        Session s = webSessionFactory.start( request );
        bind( s );
        return true;
    }



}
