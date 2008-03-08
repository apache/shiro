package org.jsecurity.session.event.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.event.ExpiredSessionEvent;
import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.StartedSessionEvent;
import org.jsecurity.session.event.StoppedSessionEvent;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultSessionEventFactory implements SessionEventFactory {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public DefaultSessionEventFactory() {}

    public SessionEvent createStartEvent( Session session ) {
        return new StartedSessionEvent( this, session.getId() );
    }

    public SessionEvent createStopEvent( Session session ) {
        return new StoppedSessionEvent( this, session.getId() );
    }

    public SessionEvent createExpirationEvent( Session session ) {
        return new ExpiredSessionEvent( this, session.getId() );
    }
}
