package org.apache.shiro.config.event;

import java.util.Map;

public class InstantiatedBeanEvent extends BeanEvent {
    public InstantiatedBeanEvent(final String beanName, final Object bean, final Map<String, Object> beanContext) {
        super(beanName, bean, beanContext);
    }
}
