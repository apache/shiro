package org.jsecurity.session.event;

/**
 * Created by IntelliJ IDEA. User: lhazlewood Date: Jul 15, 2005 Time: 9:58:08 AM To change this
 * template use File | Settings | File Templates.
 */
public interface SessionEventPublisher {

    void publish( SessionEvent event );

    void addSessionEventListener( SessionEventListener listener );

    void removeSessionEventListener( SessionEventListener listener );
}
