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
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.util.WebUtils;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
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
 * <p/>
 * This filter is a redirect helper, not an access control. By default the port is taken from
 * {@link ServletRequest#getServerPort()}, which most containers derive from the {@code Host} header
 * (or from forwarded headers when so configured), so a client can influence it. Restrictions that must hold,
 * such as limiting a path to an internal listener, belong in listener or network configuration and in
 * authentication and authorization filters.
 * <p/>
 * Behind a reverse proxy or load balancer, leave {@link #setUseLocalPort(boolean) useLocalPort} off, since the
 * container's local port is then not the port the client used.
 *
 * @since 1.0
 */
@SuppressWarnings("checkstyle:JavadocVariable")
public class PortFilter extends AuthorizationFilter {

    public static final int DEFAULT_HTTP_PORT = 80;
    public static final String HTTP_SCHEME = "http";

    private int port = DEFAULT_HTTP_PORT;
    private boolean useLocalPort;

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isUseLocalPort() {
        return useLocalPort;
    }

    /**
     * Sets whether the access check compares the required port with {@link ServletRequest#getLocalPort()},
     * the port the container actually accepted the connection on, instead of
     * {@link ServletRequest#getServerPort()}, which a client can influence through the {@code Host} header.
     * Only enable this when clients connect directly to the container, not through a proxy that changes the port.
     * The redirect issued on denial is not affected. Defaults to {@code false}.
     *
     * @param useLocalPort whether to compare against the local port
     * @since 3.0.2
     */
    public void setUseLocalPort(boolean useLocalPort) {
        this.useLocalPort = useLocalPort;
    }

    protected int toPort(Object mappedValue) {
        String[] ports = (String[]) mappedValue;
        if (ports == null || ports.length == 0) {
            return getPort();
        }
        if (ports.length > 1) {
            throw new ConfigurationException("PortFilter can only be configured with a single port.  You have "
                    + "configured " + ports.length + ": " + StringUtils.toString(ports));
        }
        return Integer.parseInt(ports[0]);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        int requiredPort = toPort(mappedValue);
        int requestPort = useLocalPort ? request.getLocalPort() : request.getServerPort();
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
