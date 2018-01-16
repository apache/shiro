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

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

public class WebEnvironmentStub implements WebEnvironment, MutableWebEnvironment {

    private FilterChainResolver filterChainResolver;

    private WebSecurityManager webSecurityManager;

    private ServletContext servletContext;


    @Override
    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    @Override
    public void setFilterChainResolver(FilterChainResolver filterChainResolver) {
        this.filterChainResolver = filterChainResolver;
    }

    @Override
    public ServletContext getServletContext() {
        return servletContext;
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @Override
    public WebSecurityManager getWebSecurityManager() {
        return webSecurityManager;
    }

    @Override
    public void setWebSecurityManager(WebSecurityManager webSecurityManager) {
        this.webSecurityManager = webSecurityManager;
    }

    @Override
    public SecurityManager getSecurityManager() {
        return getWebSecurityManager();
    }
}
