package org.jsecurity.context.support;

import org.jsecurity.context.SecurityContextException;

/**
 * Exception thrown when a <tt>SecurityContext</tt> is accessed that has been invalidated.  Usually this occurs
 * when accessing a <tt>SecurityContext</tt> whose {@link org.jsecurity.context.SecurityContext#invalidate()} method
 * has been called.  
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class InvalidSecurityContextException extends SecurityContextException {

    public InvalidSecurityContextException() {
        super();
    }

    public InvalidSecurityContextException( String message ) {
        super( message );
    }

    public InvalidSecurityContextException( Throwable cause ) {
        super( cause );
    }

    public InvalidSecurityContextException( String message, Throwable cause ) {
        super( message, cause );
    }
}
