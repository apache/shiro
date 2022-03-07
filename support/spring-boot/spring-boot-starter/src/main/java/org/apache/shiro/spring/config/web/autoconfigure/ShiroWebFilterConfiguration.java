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
package org.apache.shiro.spring.config.web.autoconfigure;

import javax.servlet.DispatcherType;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * @since 1.4.0
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "shiro.web.enabled", matchIfMissing = true)
public class ShiroWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {

    public static final String REGISTRATION_BEAN_NAME = "filterShiroFilterRegistrationBean";
    public static final String FILTER_NAME = "shiroFilter";

    @Bean
    @ConditionalOnMissingBean
    @Override
    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
        return super.shiroFilterFactoryBean();
    }

    @Bean(name = REGISTRATION_BEAN_NAME)
    @ConditionalOnMissingBean(name = REGISTRATION_BEAN_NAME)
    protected FilterRegistrationBean<AbstractShiroFilter> filterShiroFilterRegistrationBean() throws Exception {

        FilterRegistrationBean<AbstractShiroFilter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.INCLUDE, DispatcherType.ERROR);
        filterRegistrationBean.setFilter((AbstractShiroFilter) shiroFilterFactoryBean().getObject());
        filterRegistrationBean.setName(FILTER_NAME);
        filterRegistrationBean.setOrder(1);

        return filterRegistrationBean;
    }

    @Bean(name = "globalFilters")
    @ConditionalOnMissingBean
    protected List<String> globalFilters() {
        return super.globalFilters();
    }
}
