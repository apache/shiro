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

import org.apache.shiro.web.config.ShiroFilterConfiguration;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;

import javax.inject.Inject;

/**
 * Shiro filter that is managed by and receives its filter chain configurations from Guice.  The convenience method to
 * map this filter to your application is
 * {@link ShiroWebModule#bindGuiceFilter(com.google.inject.Binder) bindGuiceFilter}.
 */
public class GuiceShiroFilter extends AbstractShiroFilter {
    @SuppressWarnings("checkstyle:LineLength")
    @Inject
    GuiceShiroFilter(WebSecurityManager webSecurityManager, FilterChainResolver filterChainResolver, ShiroFilterConfiguration filterConfiguration) {
        this.setSecurityManager(webSecurityManager);
        this.setFilterChainResolver(filterChainResolver);
        this.setShiroFilterConfiguration(filterConfiguration);
    }
}
