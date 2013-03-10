package org.apache.shiro.config.event;

import java.util.Map;

/**
 * Event triggered when a configured bean has been instantiated and fully configured but right before the bean has been
 * initialized.
 *
 * @since 1.3
 * @see InstantiatedBeanEvent
 * @see org.apache.shiro.util.Initializable Initializable
 * @see InitializedBeanEvent
 * @see DestroyedBeanEvent
 */
public class ConfiguredBeanEvent extends BeanEvent {

    public ConfiguredBeanEvent(final String beanName, final Object bean, final Map<String, Object> beanContext) {
        super(beanName, bean, beanContext);
    }
}
