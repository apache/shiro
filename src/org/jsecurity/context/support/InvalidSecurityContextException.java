package org.jsecurity.context.support;

import org.jsecurity.context.SecurityContextException;

/**
 * TODO class JavaDoc
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
