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
package org.apache.shiro.web.filter.authz;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Filter which requires a request to be over SSL.  Access is allowed if the request is received on the configured
 * server {@link #setPort(int) port} <em>and</em> the
 * {@code request.}{@link javax.servlet.ServletRequest#isSecure() isSecure()}.  If either condition is {@code false},
 * the filter chain will not continue.
 * <p/>
 * The {@link #getPort() port} property defaults to {@code 443} and also additionally guarantees that the
 * request scheme is always 'https' (except for port 80, which retains the 'http' scheme).
 * <p/>
 * Example config:
 * <pre>
 * [urls]
 * /secure/path/** = ssl
 * </pre>
 *
 * @since 1.0
 */
public class SslFilter extends PortFilter {

    public static final int DEFAULT_HTTPS_PORT = 443;
    public static final String HTTPS_SCHEME = "https";

    public SslFilter() {
        setPort(DEFAULT_HTTPS_PORT);
    }

    @Override
    protected String getScheme(String requestScheme, int port) {
        if (port == DEFAULT_HTTP_PORT) {
            return PortFilter.HTTP_SCHEME;
        } else {
            return HTTPS_SCHEME;
        }
    }

    /**
     * Retains the parent method's port-matching behavior but additionally guarantees that the
     *{@code ServletRequest.}{@link javax.servlet.ServletRequest#isSecure() isSecure()}.  If the port does not match or
     * the request is not secure, access is denied.
     *
     * @param request     the incoming {@code ServletRequest}
     * @param response    the outgoing {@code ServletResponse} - ignored in this implementation
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings - ignored by this implementation.
     * @return {@code true} if the request is received on an expected SSL port and the
     * {@code request.}{@link javax.servlet.ServletRequest#isSecure() isSecure()}, {@code false} otherwise.
     * @throws Exception if the call to {@code super.isAccessAllowed} throws an exception.
     * @since 1.2
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return super.isAccessAllowed(request, response, mappedValue) && request.isSecure();
    }
}
