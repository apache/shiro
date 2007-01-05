package org.jsecurity.util;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.session.Session;

/**
 * Utility method class used to bind and unbind {@link Session Session}s and
 * {@link org.jsecurity.context.SecurityContext SecurityContext}s to the thread.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class ThreadUtils {

    private ThreadUtils(){}

    public static void bindToThread( SecurityContext authCtx ) {
        if ( authCtx != null ) {
            ThreadContext.put( ThreadContext.SECURITY_CONTEXT_KEY, authCtx );
        }
    }

    public static void unbindSecurityContextFromThread() {
        ThreadContext.remove( ThreadContext.SECURITY_CONTEXT_KEY );
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
