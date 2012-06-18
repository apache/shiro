package org.apache.shiro.event;

import java.util.Date;
import java.util.EventObject;

/**
 * @since 1.3
 */
public class ShiroEvent extends EventObject {

    private final long timestamp; //millis since Epoch (UTC time zone).

    public ShiroEvent(Object source) {
        super(source);
        this.timestamp = new Date().getTime();
    }

    public long getTimestamp() {
        return timestamp;
    }
}
