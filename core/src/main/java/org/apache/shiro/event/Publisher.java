package org.apache.shiro.event;

/**
 * @since 1.3
 */
public interface Publisher {

    void publish(Object event);
}
