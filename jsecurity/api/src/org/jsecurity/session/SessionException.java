package org.jsecurity.session;

/**
 * General SecurityException attributed to problems during interaction with the system during
 * a session.
 *
 * @author Les Hazlewood
 */
public class SessionException extends SecurityException {
    public SessionException() {
        super();
    }

    public SessionException( String s ) {
        super( s );
    }

    public SessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    public SessionException( Throwable cause ) {
        super( cause );
    }

}
