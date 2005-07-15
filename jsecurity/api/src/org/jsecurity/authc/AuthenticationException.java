package org.jsecurity.authc;

/**
 * General exception thrown due to an error during the Authentication process.
 *
 * @author Les Hazlewood
 */
public class AuthenticationException extends SecurityException {

    public AuthenticationException() {
        super();
    }

    public AuthenticationException( String message ) {
        super( message );
    }

    public AuthenticationException( Throwable cause ) {
        super( cause );
    }

    public AuthenticationException( String message, Throwable cause ) {
        super( message, cause );
    }
}
