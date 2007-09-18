package org.jsecurity.util;

import org.jsecurity.JSecurityException;

/**
 * Runtime exception thrown by the framework when unable to instantiate a Class via reflection.
 *
 * @author Les Hazlewood
 */
public class InstantiationException extends JSecurityException {

    public InstantiationException() {
        super();
    }

    public InstantiationException( String message ) {
        super( message );
    }

    public InstantiationException( Throwable cause ) {
        super( cause );
    }

    public InstantiationException( String message, Throwable cause ) {
        super( message, cause );
    }
}
