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
package org.apache.shiro.spring.web.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.config.ShiroFilterConfiguration;
import org.apache.shiro.web.filter.mgt.DefaultFilter;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import jakarta.servlet.Filter;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @since 1.4.0
 */
public class AbstractShiroWebFilterConfiguration {

    @Autowired
    protected SecurityManager securityManager;

    @Autowired
    protected ShiroFilterChainDefinition shiroFilterChainDefinition;

    @Autowired(required = false)
    protected ShiroFilterConfiguration shiroFilterConfiguration;

    @Autowired
    protected ListableBeanFactory beanFactory;

    @Value("#{ @environment['shiro.loginUrl'] ?: '/login.jsp' }")
    protected String loginUrl;

    @Value("#{ @environment['shiro.successUrl'] ?: '/' }")
    protected String successUrl;

    @Value("#{ @environment['shiro.unauthorizedUrl'] ?: null }")
    protected String unauthorizedUrl;

    @Value("#{ @environment['shiro.caseInsensitive'] ?: false }")
    protected boolean caseInsensitive;

    protected List<String> globalFilters() {
        return Collections.singletonList(DefaultFilter.invalidRequest.name());
    }

    protected ShiroFilterConfiguration shiroFilterConfiguration() {
        return shiroFilterConfiguration != null
                ? shiroFilterConfiguration
                : new ShiroFilterConfiguration();
    }

    /**
     * Collects Filter beans from the application context, excluding any AbstractShiroFilter
     * instances to avoid circular dependency with ShiroFilterFactoryBean.
     *
     * @return a map of filter names to Filter instances
     */
    protected Map<String, Filter> filterMap() {
        Map<String, Filter> filterMap = new LinkedHashMap<>();
        Map<String, Filter> allFilters = beanFactory.getBeansOfType(Filter.class);
        for (Map.Entry<String, Filter> entry : allFilters.entrySet()) {
            // Exclude AbstractShiroFilter instances to avoid circular dependency
            if (!(entry.getValue() instanceof AbstractShiroFilter)) {
                filterMap.put(entry.getKey(), entry.getValue());
            }
        }
        return filterMap;
    }

    protected ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();

        filterFactoryBean.setLoginUrl(loginUrl);
        filterFactoryBean.setSuccessUrl(successUrl);
        filterFactoryBean.setUnauthorizedUrl(unauthorizedUrl);
        filterFactoryBean.setCaseInsensitive(caseInsensitive);

        filterFactoryBean.setSecurityManager(securityManager);
        filterFactoryBean.setShiroFilterConfiguration(shiroFilterConfiguration());
        filterFactoryBean.setGlobalFilters(globalFilters());
        filterFactoryBean.setFilterChainDefinitionMap(shiroFilterChainDefinition.getFilterChainMap());

        Map<String, Filter> filterMap = filterMap();
        if (!filterMap.isEmpty()) {
            filterFactoryBean.setFilters(filterMap);
        }

        return filterFactoryBean;
    }
}
