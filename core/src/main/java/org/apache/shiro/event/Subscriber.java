package org.apache.shiro.event;

/**
 * @since 1.3
 */
public interface Subscriber {

    void onEvent(Object event);
}
