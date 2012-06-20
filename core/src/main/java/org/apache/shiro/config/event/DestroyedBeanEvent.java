package org.apache.shiro.config.event;

import java.util.Map;

public class DestroyedBeanEvent extends BeanEvent {
    public DestroyedBeanEvent(final String beanName, final Object bean, final Map<String, Object> beanContext) {
        super(beanName, bean, beanContext);
    }
}
