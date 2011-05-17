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

import org.apache.shiro.env.Environment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.servlet.ServletContext;

/**
 * A web-specific {@link Environment} instance, used in web applications.
 *
 * @since 1.2
 */
public interface WebEnvironment extends Environment {

    /**
     * Returns the web application's {@code FilterChainResolver} if one has been configured or {@code null} if one
     * is not available.
     *
     * @return the web application's {@code FilterChainResolver} if one has been configured or {@code null} if one
     *         is not available.
     */
    FilterChainResolver getFilterChainResolver();

    /**
     * Returns the {@code ServletContext} associated with this {@code WebEnvironment} instance.  A web application
     * typically only has a single {@code WebEnvironment} associated with its {@code ServletContext}.
     *
     * @return the {@code ServletContext} associated with this {@code WebEnvironment} instance.
     */
    ServletContext getServletContext();

    /**
     * Returns the web application's security manager instance.
     *
     * @return the web application's security manager instance.
     */
    WebSecurityManager getWebSecurityManager();
}
