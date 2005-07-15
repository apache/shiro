package org.jsecurity.authc;

/**
 * Thrown when attempting to authenticate with a principal that doesn't exist in the system (e.g.
 * by specifying a username that doesn't relate to a user account).
 *
 * <p>Whether or not an application wishes to alert a user logging in to the system of this fact is
 * at the discretion of those responsible for designing the view and what happens when this
 * case occurs.
 *
 * @author Les Hazlewood
 */
public class UnknownAccountException extends AccountException {

    public UnknownAccountException() {
        super();
    }

    public UnknownAccountException( String message ) {
        super( message );
    }

    public UnknownAccountException( Throwable cause ) {
        super( cause );
    }

    public UnknownAccountException( String message, Throwable cause ) {
        super( message, cause );
    }
}
