package org.jsecurity.authc;

/**
 * Thrown when an authentication attempt has been received for an account that has already been
 * authenticated (i.e. logged-in), and the system is configured to prevent such concurrent access.
 *
 * <p>This is useful when an application must ensure that only one person is logged-in to a single
 * account at any given time.  Sometimes account names and passwords are lazily given away
 * to many people for easy access to a system.  Such behavior is undesirable in systems where
 * users are accountable for their actions, such as in government applications, or when licensing
 * agreements must be maintained, such as those which only allow 1 user per paid license.
 *
 * <p>By disallowing concurrent access, such systems can ensure that each authenticated session
 * corresponds to one and only one user.
 *
 * @author Les Hazlewood
 */
public class ConcurrentAccessException extends AccountException {

    public ConcurrentAccessException() {
        super();
    }

    public ConcurrentAccessException( String message ) {
        super( message );
    }

    public ConcurrentAccessException( Throwable cause ) {
        super( cause );
    }

    public ConcurrentAccessException( String message, Throwable cause ) {
        super( message, cause );
    }

}
