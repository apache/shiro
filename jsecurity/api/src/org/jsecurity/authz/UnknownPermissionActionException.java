package org.jsecurity.authz;

/**
 * An exception thrown when an {@link InstancePermission} is constructed with an element in the
 * actions string that is unknown to the <tt>InstancePermission</tt> implementation.
 *
 * @author Les Hazlewood
 */
public class UnknownPermissionActionException extends RuntimeException {

    public UnknownPermissionActionException() {
    }

    public UnknownPermissionActionException( String message ) {
        super( message );
    }

    public UnknownPermissionActionException( String message, Throwable cause ) {
        super( message, cause );
    }

    public UnknownPermissionActionException( Throwable cause ) {
        super( cause );
    }

}
