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

/**
 * Filter which requires a request to be over SSL.
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
}
