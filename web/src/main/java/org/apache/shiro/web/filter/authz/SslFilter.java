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
 * Convenience filter which requires a request to be over SSL.  This filter has the same effect as of using the
 * {@link PortFilter} with configuration defaulting to port {@code 443}.  That is, these two configs are the same:
 *
 * <pre>
 * /some/path/** = port[443]
 * /some/path/** = ssl
 * </pre>
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SslFilter extends PortFilter {

    public static final int DEFAULT_SSL_PORT = 443;

    @Override
    protected int toPort(Object mappedValue) {
        String[] ports = (String[]) mappedValue;
        if (ports == null || ports.length == 0) {
            return DEFAULT_SSL_PORT;
        }
        return super.toPort(mappedValue);
    }
}
