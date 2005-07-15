package org.jsecurity.session.event;

/**
 * Created by IntelliJ IDEA. User: lhazlewood Date: Jul 15, 2005 Time: 9:58:48 AM To change this
 * template use File | Settings | File Templates.
 */
public interface SessionEventListener {

    void sessionStarted( SessionEvent event );

    void sessionStopped( SessionEvent event );
    
    void sessionExpired( SessionEvent event );

}
