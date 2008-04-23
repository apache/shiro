package org.jsecurity.io;

import org.jsecurity.JSecurityException;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Apr 23, 2008 8:58:22 AM
 */
public class SerializationException extends JSecurityException {

    public SerializationException() {
        super();
    }

    public SerializationException(String message) {
        super(message);
    }

    public SerializationException(Throwable cause) {
        super(cause);
    }

    public SerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
