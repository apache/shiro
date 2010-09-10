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

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * A Filter that requires the request to be on a specific port, and if not, redirects to the same URL on that port.
 * <p/>
 * Example config:
 * <pre>
 * [filters]
 * port.port = 80
 * <p/>
 * [urls]
 * /some/path/** = port
 * # override for just this path:
 * /another/path/** = port[8080]
 * </pre>
 *
 * @since 1.0
 */
public class PortFilter extends AuthorizationFilter {

    public static final int DEFAULT_HTTP_PORT = 80;
    public static final String HTTP_SCHEME = "http";

    private int port = DEFAULT_HTTP_PORT;

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    protected int toPort(Object mappedValue) {
        String[] ports = (String[]) mappedValue;
        if (ports == null || ports.length == 0) {
            return getPort();
        }
        if (ports.length > 1) {
            throw new ConfigurationException("PortFilter can only be configured with a single port.  You have " +
                    "configured " + ports.length + ": " + StringUtils.toString(ports));
        }
        return Integer.parseInt(ports[0]);
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        int requiredPort = toPort(mappedValue);
        int requestPort = request.getServerPort();
        return requiredPort == requestPort;
    }

    protected String getScheme(String requestScheme, int port) {
        if (port == DEFAULT_HTTP_PORT) {
            return HTTP_SCHEME;
        } else if (port == SslFilter.DEFAULT_HTTPS_PORT) {
            return SslFilter.HTTPS_SCHEME;
        } else {
            return requestScheme;
        }
    }

    /**
     * Redirects the request to the same exact incoming URL, but with the port listed in the filter's configuration.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @param mappedValue the config specified for the filter in the matching request's filter chain.
     * @return {@code false} always to force a redirect.
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {

        //just redirect to the specified port:
        int port = toPort(mappedValue);

        String scheme = getScheme(request.getScheme(), port);

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://");
        sb.append(request.getServerName());
        if (port != DEFAULT_HTTP_PORT && port != SslFilter.DEFAULT_HTTPS_PORT) {
            sb.append(":");
            sb.append(port);
        }
        if (request instanceof HttpServletRequest) {
            sb.append(WebUtils.toHttp(request).getRequestURI());
            String query = WebUtils.toHttp(request).getQueryString();
            if (query != null) {
                sb.append("?").append(query);
            }
        }

        WebUtils.issueRedirect(request, response, sb.toString());

        return false;
    }
}
