package org.apache.shiro.config.event;

import java.util.EventObject;
import java.util.Map;

public class BeanEvent extends EventObject {

    private String beanName;
    private Object bean;
    private final Map<String, Object> beanContext;

    public BeanEvent(final String beanName, final Object bean, final Map<String, Object> beanContext) {
        super(bean);
        this.beanName = beanName;
        this.bean = bean;
        this.beanContext = beanContext;
    }

    public String getBeanName() {
        return beanName;
    }

    public Object getBean() {
        return bean;
    }

    public Map<String, Object> getBeanContext() {
        return beanContext;
    }
}
