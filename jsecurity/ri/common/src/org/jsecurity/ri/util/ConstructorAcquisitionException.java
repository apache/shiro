package org.jsecurity.ri.util;

import org.jsecurity.JSecurityException;

/**
 * Exception thrown when trying to construct a {@link java.security.Permission Permission} via reflection, and
 * JSecurity can't find a suitable constructor with which to instantiate the Permission class.
 *
 * @author Les Hazlewood
 */
public class ConstructorAcquisitionException extends JSecurityException {

    public ConstructorAcquisitionException() {
        super();
    }

    public ConstructorAcquisitionException( String message ) {
        super( message );
    }

    public ConstructorAcquisitionException( Throwable cause ) {
        super( cause );
    }

    public ConstructorAcquisitionException( String message, Throwable cause ) {
        super( message, cause );
    }

}
