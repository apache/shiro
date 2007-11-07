package org.jsecurity.session.event;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public interface SessionEventListenerRegistry {
    void add( SessionEventListener listener );
    boolean remove( SessionEventListener listener );
}
