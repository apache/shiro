package org.jsecurity.authc;

/**
 * Thrown when a system is configured to only allow a certain number of authentication attempts
 * over a period of time and the current session has failed to authenticate successfully within
 * that number.  The resulting action of such an exception is applicaiton dependent, but
 * most systems either temporarily or permanently lock that account to prevent further
 * attempts.
 *
 * @author Les Hazlewood
 */
public class ExcessiveAttemptsException extends AccountException {

    public ExcessiveAttemptsException() {
        super();
    }

    public ExcessiveAttemptsException( String message ) {
        super( message );
    }

    public ExcessiveAttemptsException( Throwable cause ) {
        super( cause );
    }

    public ExcessiveAttemptsException( String message, Throwable cause ) {
        super( message, cause );
    }
}
