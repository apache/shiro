package org.jsecurity.authc;

/**
 * Thrown when attempting to authenticate and the corresponding account has been locked.
 *
 * @author Les Hazlewood
 */
public class LockedAccountException extends AccountException {

    public LockedAccountException() {
        super();    
    }

    public LockedAccountException( String message ) {
        super( message );
    }

    public LockedAccountException( Throwable cause ) {
        super( cause );
    }

    public LockedAccountException( String message, Throwable cause ) {
        super( message, cause );
    }

}
