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
package org.apache.shiro.guice.web;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.inject.Named;
import javax.servlet.ServletContext;

@Singleton
class WebGuiceEnvironment implements WebEnvironment {
    private FilterChainResolver filterChainResolver;
    private ServletContext servletContext;
    private WebSecurityManager securityManager;

    @Inject
    WebGuiceEnvironment(FilterChainResolver filterChainResolver, @Named(ShiroWebModule.NAME) ServletContext servletContext, WebSecurityManager securityManager) {
        this.filterChainResolver = filterChainResolver;
        this.servletContext = servletContext;
        this.securityManager = securityManager;

        servletContext.setAttribute(EnvironmentLoaderListener.ENVIRONMENT_ATTRIBUTE_KEY, this);
    }

    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    public ServletContext getServletContext() {
        return servletContext;
    }

    public WebSecurityManager getWebSecurityManager() {
        return securityManager;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }
}
