package org.jsecurity.session;

/**
 * Exception thrown when attempting to interact with the system under an established session
 * when that session has expired.
 *
 * @author Les Hazlewood
 */
public class ExpiredSessionException extends SessionException {

    public ExpiredSessionException() {
        super();
    }

    public ExpiredSessionException( String s ) {
        super( s );
    }

    public ExpiredSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    public ExpiredSessionException( Throwable cause ) {
        super( cause );
    }
}
