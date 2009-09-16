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
package org.apache.shiro.web.config;

import org.apache.shiro.config.Configuration;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * A {@code WebConfiguration} configures Shiro components in a web-enabled application.
 * <p/>
 * In addition to enabling configuration of a <code>SecurityManager</code>, as required by the parent
 * {@link Configuration} interface, it also allows configuration of arbitrary filter chains to be executed for any
 * given request or URI/URL by sub-interfacing the {@link FilterChainResolver} interface.
 *
 * @since 0.9
 */
public interface WebConfiguration extends Configuration {

    /**
     * Returns the filter chain that should be executed for the given request, or {@code null} if the
     * original chain should be used.
     * <p/>
     * This method allows a implementation to define arbitrary security {@link javax.servlet.Filter Filter}
     * chains for any given request or URL pattern.
     *
     * @param request       the incoming ServletRequest
     * @param response      the outgoing ServletResponse
     * @param originalChain the original {@code FilterChain} intercepted by the ShiroFilter.
     * @return the filter chain that should be executed for the given request, or {@code null} if the
     *         original chain should be used.
     * @deprecated The WebConfiguration instance should return an instance of a FilterChainResolver via the
     *             {@link #getFilterChainResolver()} method instead.
     */
    @Deprecated
    FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain);

    FilterChainResolver getFilterChainResolver();
}
