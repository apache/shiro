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
package org.apache.shiro.cdi.web;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;

@ApplicationScoped
public class CdiWebEnvironment implements WebEnvironment {

    @Inject
    private FilterChainResolver filterChainResolver;

    @Inject
    private WebSecurityManager webSecurityManager;

    @Inject
    private ServletContext servletContext;

    @Override
    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    @Override
    public SecurityManager getSecurityManager() {
        return webSecurityManager;
    }

    @Override
    public WebSecurityManager getWebSecurityManager() {
        return webSecurityManager;
    }

    @Override
    public ServletContext getServletContext() {
        return servletContext;
    }
}
