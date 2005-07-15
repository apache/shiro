package org.jsecurity.authc;

/**
 * Exception thrown due to a problem with the account
 * under which an authentication attempt is being executed.
 *
 * @author Les Hazlewood
 */
public class AccountException extends AuthenticationException {

    public AccountException() {
        super();
    }

    public AccountException( String message ) {
        super( message );
    }

    public AccountException( Throwable cause ) {
        super( cause );
    }

    public AccountException( String message, Throwable cause ) {
        super( message, cause );
    }

}
