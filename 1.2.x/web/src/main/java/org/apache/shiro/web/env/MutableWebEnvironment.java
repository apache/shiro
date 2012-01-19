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

import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

/**
 * A {@code WebEnvironment} that supports 'write' operations operations.  This mainly exists to shield
 * {@code WebEnvironment} API consumers from modification operations, which are mostly only used during Shiro
 * environment initialization.
 *
 * @since 1.2
 */
public interface MutableWebEnvironment extends WebEnvironment {

    /**
     * Sets the {@code WebEnvironment}'s {@link FilterChainResolver}.
     *
     * @param filterChainResolver the {@code WebEnvironment}'s {@link FilterChainResolver}.
     */
    void setFilterChainResolver(FilterChainResolver filterChainResolver);

    /**
     * Sets the {@link WebEnvironment}'s associated {@code ServletContext} instance.  Invoking this method merely
     * makes the {@code ServletContext} available to the underlying instance - it does not trigger initialization
     * behavior.
     *
     * @param servletContext the {@link WebEnvironment}'s associated {@code ServletContext} instance.
     */
    void setServletContext(ServletContext servletContext);

    /**
     * Sets the {@code WebEnvironment}'s {@link WebSecurityManager}.
     *
     * @param webSecurityManager the {@code WebEnvironment}'s {@link WebSecurityManager}.
     */
    void setWebSecurityManager(WebSecurityManager webSecurityManager);
}
