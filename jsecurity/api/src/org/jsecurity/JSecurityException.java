package org.jsecurity;

/**
 * Root exception for all JSecurity runtime exceptions.  This class is used as the root instead
 * of {@link java.lang.SecurityException} to remove the potential for conflicts;  many other
 * frameworks and products (such as J2EE containers) perform special operations when
 * encountering {@link java.lang.SecurityException}.
 *
 * @author Les Hazlewood
 */
public class JSecurityException extends RuntimeException {

    public JSecurityException() {
        super();
    }

    public JSecurityException( String message ) {
        super( message );
    }

    public JSecurityException( Throwable cause ) {
        super( cause );
    }

    public JSecurityException( String message, Throwable cause ) {
        super( message, cause );
    }

}
