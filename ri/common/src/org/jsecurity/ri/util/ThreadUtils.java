package org.jsecurity.ri.util;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.session.Session;

/**
 * Utility method class used to bind and unbind {@link Session Session}s and
 * {@link AuthorizationContext AuthorizationContext}s to the thread.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class ThreadUtils {

    private ThreadUtils(){}

    public static void bindToThread( AuthorizationContext authCtx ) {
        if ( authCtx != null ) {
            ThreadContext.put( ThreadContext.AUTHORIZATION_CONTEXT_KEY, authCtx );
        }
    }

    public static void unbindAuthorizationContextFromThread() {
        ThreadContext.remove( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
    }

    public static void bindToThread( Session s ) {
        if ( s != null ) {
            ThreadContext.put( ThreadContext.SESSION_KEY, s );
        }
    }

    public static void unbindSessionFromThread() {
        ThreadContext.remove( ThreadContext.SESSION_KEY );
    }

}
