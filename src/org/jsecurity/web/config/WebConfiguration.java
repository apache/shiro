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
package org.jsecurity.web.config;

import org.jsecurity.config.Configuration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since Jun 1, 2008 11:13:32 PM
 */
public interface WebConfiguration extends Configuration {

    /**
     * Returns the filter chain that should be executed for the given request, or <code>null</code> if the
     * original chain should be used.
     *
     * <p>This method allows a Configuration implementation to define arbitrary security {@link Filter Filter}
     * chains for any given request or URL pattern.
     *
     * @param request       the incoming ServletRequest
     * @param response      the outgoing ServletResponse
     * @param originalChain the original <code>FilterChain</code> intercepted by the JSecurityFilter.
     * @return the filter chain that should be executed for the given request, or <code>null</code> if the
     *         original chain should be used.
     */
    FilterChain getChain(ServletRequest request, ServletResponse response, FilterChain originalChain);
}
