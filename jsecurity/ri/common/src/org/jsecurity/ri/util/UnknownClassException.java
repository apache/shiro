package org.jsecurity.ri.util;

import org.jsecurity.JSecurityException;

/**
 * @author Les Hazlewood
 */
public class UnknownClassException extends JSecurityException {

    public UnknownClassException() {
        super();
    }

    public UnknownClassException( String message ) {
        super( message );
    }

    public UnknownClassException( Throwable cause ) {
        super( cause );
    }

    public UnknownClassException( String message, Throwable cause ) {
        super( message, cause );
    }

}
