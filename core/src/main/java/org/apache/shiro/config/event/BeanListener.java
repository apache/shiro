package org.apache.shiro.config.event;

/**
 * Extension point that provides for notification of lifecycle events in the bean configuration process.  This is an
 * extension point of the (typically) ini-based bean instantiation strategy used by default by shiro.  It is intended
 * as a bare-bones corollary to the more advanced lifecycle facilities offered in full-fledged dependency injection
 * frameworks.
 *
 * The type of event is determined by the type of the beanEvent object.  Use of {@see BeanListenerSupport} is
 * recommended.
 */
public interface BeanListener {
    void onBeanEvent(BeanEvent beanEvent);
}
