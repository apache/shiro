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

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Bootstrap listener to startup and shutdown the web application's Shiro
 * {@link WebEnvironment} at ServletContext startup and shutdown respectively.  This class exists only to
 * implement the {@link ServletContextListener} interface. All 'real' logic is done in the parent
 * {@link EnvironmentLoader} class.
 * <h2>Usage</h2>
 * Define the following in {@code web.xml}:
 * <pre>
 * &lt;listener&gt;
 *     &lt;listener-class&gt;<code>org.apache.shiro.web.env.EnvironmentLoaderListener</code>&lt;/listener-class&gt;
 * &lt;/listener&gt;
 * </pre>
 * Configuration options, such as the {@code WebEnvironment} class to instantiate as well as Shiro configuration
 * resource locations are specified as {@code ServletContext} {@code context-param}s and are documented in the
 * {@link EnvironmentLoader} JavaDoc.
 * <h2>Shiro Filter</h2>
 * This listener is almost always defined in conjunction with the
 * {@link org.apache.shiro.web.servlet.ShiroFilter ShiroFilter} to ensure security operations for web requests.  Please
 * see the {@link org.apache.shiro.web.servlet.ShiroFilter ShiroFilter} JavaDoc for more.
 *
 *
 * @see EnvironmentLoader
 * @see org.apache.shiro.web.servlet.ShiroFilter ShiroFilter
 * @since 1.2
 */
public class EnvironmentLoaderListener extends EnvironmentLoader implements ServletContextListener {

    /**
     * Initializes the Shiro {@code WebEnvironment} and binds it to the {@code ServletContext} at application
     * startup for future reference.
     *
     * @param sce the ServletContextEvent triggered upon application startup
     */
    public void contextInitialized(ServletContextEvent sce) {
        initEnvironment(sce.getServletContext());
    }

    /**
     * Destroys any previously created/bound {@code WebEnvironment} instance created by
     * the {@link #contextInitialized(javax.servlet.ServletContextEvent)} method.
     *
     * @param sce the ServletContextEvent triggered upon application shutdown
     */
    public void contextDestroyed(ServletContextEvent sce) {
        destroyEnvironment(sce.getServletContext());
    }
}
