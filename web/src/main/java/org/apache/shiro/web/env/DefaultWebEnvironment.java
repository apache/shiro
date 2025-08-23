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
package org.apache.shiro.web.env;

import org.apache.shiro.env.DefaultEnvironment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.config.ShiroFilterConfiguration;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import jakarta.servlet.ServletContext;
import java.util.Map;

/**
 * Default {@link WebEnvironment} implementation based on a backing {@link Map} instance.
 *
 * @since 1.2
 */
public class DefaultWebEnvironment extends DefaultEnvironment implements MutableWebEnvironment {

    private static final String DEFAULT_FILTER_CHAIN_RESOLVER_NAME = "filterChainResolver";
    private static final String SHIRO_FILTER_CONFIG_NAME = "shiroFilter";

    private ServletContext servletContext;

    private ShiroFilterConfiguration filterConfiguration;

    public DefaultWebEnvironment() {
        super();
    }

    public FilterChainResolver getFilterChainResolver() {
        return getObject(DEFAULT_FILTER_CHAIN_RESOLVER_NAME, FilterChainResolver.class);
    }

    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        setObject(DEFAULT_FILTER_CHAIN_RESOLVER_NAME, filterChainResolver);
    }

    @Override
    public SecurityManager getSecurityManager() throws IllegalStateException {
        return getWebSecurityManager();
    }

    @Override
    public void setSecurityManager(SecurityManager securityManager) {
        assertWebSecurityManager(securityManager);
        super.setSecurityManager(securityManager);
    }

    public WebSecurityManager getWebSecurityManager() {
        SecurityManager sm = super.getSecurityManager();
        assertWebSecurityManager(sm);
        return (WebSecurityManager) sm;
    }

    public void setWebSecurityManager(WebSecurityManager wsm) {
        super.setSecurityManager(wsm);
    }

    private void assertWebSecurityManager(SecurityManager sm) {
        if (!(sm instanceof WebSecurityManager)) {
            String msg = "SecurityManager instance must be a " + WebSecurityManager.class.getName() + " instance.";
            throw new IllegalStateException(msg);
        }
    }

    public ServletContext getServletContext() {
        return this.servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }


    @Override
    public void setShiroFilterConfiguration(ShiroFilterConfiguration filterConfiguration) {
        setObject(SHIRO_FILTER_CONFIG_NAME, filterConfiguration);
    }

    @Override
    public ShiroFilterConfiguration getShiroFilterConfiguration() {
        ShiroFilterConfiguration config = getObject(SHIRO_FILTER_CONFIG_NAME, ShiroFilterConfiguration.class);
        // Use the default configuration if config is null
        if (config == null) {
            config = MutableWebEnvironment.super.getShiroFilterConfiguration();
            setShiroFilterConfiguration(config);
        }
        return config;
    }
}
