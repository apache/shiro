package org.apache.shiro.event;

import java.util.EventObject;

/**
 * Root class for all of Shiro's event classes.  Provides access to the timestamp when the event occurred.
 *
 * @since 1.3
 */
public abstract class Event extends EventObject {

    private final long timestamp; //millis since Epoch (UTC time zone).

    public Event(Object source) {
        super(source);
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Returns the timestamp when this event occurred as the number of milliseconds since Epoch (UTC time zone).
     *
     * @return the timestamp when this event occurred as the number of milliseconds since Epoch (UTC time zone).
     */
    public long getTimestamp() {
        return this.timestamp;
    }
}
