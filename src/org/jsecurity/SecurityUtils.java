package org.jsecurity;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.SecurityContextException;
import org.jsecurity.util.ThreadContext;

/**
 * Simple utility class to perform common JSecurity operations in an application.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class SecurityUtils {

    /**
     * Returns the currently accessible <tt>SecurityContext</tt> available to the calling code.
     *
     * <p>This method is provided as a way of obtaining a <tt>SecurityContext</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * <p><b>PLEASE NOTE:</b> Currently, this method should only be called in web and server-side environments.  If
     * you're operating in a standalone application environment, you should instead create your own SecurityUtils
     * class that returns the <tt>SecurityContext</tt> in your environment-specific manner.
     *
     * @return the currently accessible <tt>SecurityContext</tt> accessible to the calling code.
     */
    public static SecurityContext getSecurityContext() {
        SecurityContext secCtx = ThreadContext.getSecurityContext();
        if( secCtx == null ) {
            throw new SecurityContextException( "No security context is bound to the current thread.  " +
                    "Make sure that a SecurityContextWebInterceptor or SecurityContextFilter is configured." );
        }
        return secCtx;
    }
}
