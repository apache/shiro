package org.jsecurity.ri.context;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.ri.util.ThreadContext;
import org.jsecurity.session.Session;

/**
 * Retrieves all security context data from the currently executing thread (via the {@link ThreadContext}).  This
 * implementation is most widely used in multi-threaded server environments such as EJB and Servlet containers.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class ThreadLocalSecurityContext extends SecurityContext {

    public Session getSession() {
        return (Session) ThreadContext.get( ThreadContext.SESSION_KEY );
    }

    public AuthorizationContext getAuthorizationContext() {
        return (AuthorizationContext)ThreadContext.get( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
    }

    public void invalidate() {

        try {
            Session s = getSession();
            if ( s != null ) {
                s.stop();
            }
        } finally {
            ThreadContext.remove( ThreadContext.SESSION_KEY );
            ThreadContext.remove( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
        }
    }

}
