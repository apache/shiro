package org.apache.shiro.event;

/**
 * @since 1.3
 */
public interface SubscriberRegistry {

    void subscribe(Subscriber subscriber);

    void subscribe(Subscriber subscriber, Class... messageTypes);

    void unsubscribe(Subscriber subscriber);

    void unsubscribe(Subscriber subscriber, Class... messageTypes);
}
