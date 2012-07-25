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
package org.apache.shiro.web.servlet;

import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.util.WebUtils;

/**
 * Primary Shiro Filter for web applications configuring Shiro via Servlet &lt;listener&gt; in web.xml.
 * <p/>
 * As of Shiro 1.2, this is Shiro's preferred filter for {@code web.xml} configuration.  It expects the presence of a
 * Shiro {@link org.apache.shiro.web.env.WebEnvironment WebEnvironment} in the {@code ServletContext}, also
 * configured via {@code web.xml}.
 * <h2>Usage</h2>
 * As this Filter expects an available {@link org.apache.shiro.web.env.WebEnvironment WebEnvironment} instance to
 * be configured, it must be defined in {@code web.xml} with the companion
 * {@link org.apache.shiro.web.env.EnvironmentLoaderListener EnvironmentLoaderListener}, which performs the necessary
 * environment setup.  For example:
 * <pre>
 * &lt;listener&gt;
 *     &lt;listener-class&gt;{@link org.apache.shiro.web.env.EnvironmentLoaderListener}&lt;/listener-class&gt;
 * &lt;/listener&gt;
 * ...
 * &lt;filter&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;filter-class&gt;org.apache.shiro.web.servlet.ShiroFilter&lt;/filter-class&gt;
 * &lt;/filter&gt;
 *
 * &lt;-- Filter all web requests.  This filter mapping is typically declared
 *     before all others to ensure any other filters are secured as well: --&gt;
 * &lt;filter-mapping&gt;
 *     &lt;filter-name&gt;ShiroFilter&lt;/filter-name&gt;
 *     &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;
 * </pre>
 * Configuration options (configuration file paths, etc) are specified as part of the
 * {@code EnvironmentLoaderListener} configuration.  See the
 * {@link org.apache.shiro.web.env.EnvironmentLoader EnvironmentLoader} JavaDoc for configuration options.
 *
 * @see org.apache.shiro.web.env.EnvironmentLoader EnvironmentLoader
 * @see org.apache.shiro.web.env.EnvironmentLoaderListener EnvironmentLoaderListener
 * @see <a href="http://shiro.apache.org/web.html">Apache Shiro Web Documentation</a>
 * @since 1.2
 */
public class ShiroFilter extends AbstractShiroFilter {

    /**
     * Configures this instance based on the existing {@link org.apache.shiro.web.env.WebEnvironment} instance
     * available to the currently accessible {@link #getServletContext() servletContext}.
     *
     * @see org.apache.shiro.web.env.EnvironmentLoaderListener
     * @since 1.2
     */
    @Override
    public void init() throws Exception {
        WebEnvironment env = WebUtils.getRequiredWebEnvironment(getServletContext());

        setSecurityManager(env.getWebSecurityManager());

        FilterChainResolver resolver = env.getFilterChainResolver();
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }
    }
}
