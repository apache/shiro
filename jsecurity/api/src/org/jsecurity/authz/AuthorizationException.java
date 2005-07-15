package org.jsecurity.authz;

/**
 * Exception thrown if there is a problem during authorization.
 *
 * @author Les Hazlewood
 */
public class AuthorizationException extends SecurityException {

    public AuthorizationException() {
        super();
    }

    public AuthorizationException( String s ) {
        super( s );
    }

    public AuthorizationException( Throwable cause ) {
        super( cause );
    }

    public AuthorizationException( String message, Throwable cause ) {
        super( message, cause );
    }
}
