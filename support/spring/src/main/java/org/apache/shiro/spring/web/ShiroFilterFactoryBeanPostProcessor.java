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
package org.apache.shiro.spring.web;

import jakarta.servlet.Filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.PriorityOrdered;
import java.util.Map;

/**
 * This implementation is a {@link BeanPostProcessor} and will acquire
 * any {@link Filter Filter} beans defined independently in your Spring application context.  Upon
 * discovery, they will be automatically added to the {@link ShiroFilterFactoryBean#setFilters(Map) map} keyed by the bean ID.
 * That ID can then be used in the filter chain definitions, for example:
 *
 * @since 3.0.0
 */
public class ShiroFilterFactoryBeanPostProcessor implements BeanPostProcessor, PriorityOrdered {
    private static final Logger LOGGER = LoggerFactory.getLogger(ShiroFilterFactoryBeanPostProcessor.class);

    private final ShiroFilterFactoryBean shiroFilterFactoryBean;

    public ShiroFilterFactoryBeanPostProcessor(ShiroFilterFactoryBean shiroFilterFactoryBean) {
        this.shiroFilterFactoryBean = shiroFilterFactoryBean;
    }

    /**
     * Inspects a bean, and if it implements the {@link Filter} interface, automatically adds that filter
     * instance to the internal {@link ShiroFilterFactoryBean#setFilters(Map) filters map} that will be referenced
     * later during filter chain construction.
     */
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof Filter filter) {
            LOGGER.debug("Found filter chain candidate filter '{}'", beanName);
            shiroFilterFactoryBean.applyGlobalPropertiesIfNecessary(filter);
            shiroFilterFactoryBean.getFilters().put(beanName, filter);
        } else {
            LOGGER.trace("Ignoring non-Filter bean '{}'", beanName);
        }
        return bean;
    }

    /**
     * Does nothing - only exists to satisfy the BeanPostProcessor interface and immediately returns the
     * {@code bean} argument.
     */
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }
}
