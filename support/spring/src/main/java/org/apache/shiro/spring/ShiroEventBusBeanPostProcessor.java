/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.spring;

import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.lang.util.ClassUtils;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

import java.util.List;

/**
 * Spring {@link BeanPostProcessor} that detects, {@link EventBusAware} and classes containing {@link Subscribe @Subscribe} methods.
 * Any classes implementing EventBusAware will have the setEventBus() method called with the <code>eventBus</code>. Any
 * classes discovered with methods that are annotated with @Subscribe will be automaticly registered with the EventBus.
 *
 * <p><strong>NOTE:</strong> in a Spring environment implementing EventBusAware is not necessary, as you can just inject the EventBus with
 * {@link org.springframework.beans.factory.annotation.Autowire @Autowire}.</p>
 *
 * @see EventBusAware
 * @see Subscribe
 * @since 1.4
 */
public class ShiroEventBusBeanPostProcessor implements BeanPostProcessor {

    final private EventBus eventBus;

    public ShiroEventBusBeanPostProcessor(EventBus eventBus) {
        this.eventBus = eventBus;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof EventBusAware) {
            ((EventBusAware) bean).setEventBus(eventBus);
        }
        else if (isEventSubscriber(bean)) {
            eventBus.register(bean);
        }

        return bean;
    }

    private boolean isEventSubscriber(Object bean) {
        List annotatedMethods = ClassUtils.getAnnotatedMethods(bean.getClass(), Subscribe.class);
        return !CollectionUtils.isEmpty(annotatedMethods);
    }

}
