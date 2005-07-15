package org.jsecurity.session.event;

import java.util.Calendar;
import java.util.EventObject;
import java.io.Serializable;

/**
 * General event concerning a {@link org.jsecurity.session.Session} instance.
 */
public abstract class SessionEvent extends EventObject {

    protected Calendar timestamp = Calendar.getInstance();

    protected final Serializable sessionId;

    public SessionEvent( Serializable sessionId ) {
        /* Dummy source.  Most times we don't care about the object that actually generates the
           event in a client-server system (which is usually the SessionManager). */
        this( new Object(), sessionId );
    }

    public SessionEvent( Object source, Serializable sessionId ) {
        super( source );
        this.sessionId = sessionId;
    }

    public Calendar getTimestamp() {
        return timestamp;
    }

    public void setTimestamp( Calendar timestamp ) {
        this.timestamp = timestamp;
    }
}
