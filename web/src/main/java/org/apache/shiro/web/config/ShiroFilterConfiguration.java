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

import org.apache.shiro.SecurityUtils;

/**
 * Configuration for Shiro's root level servlet filter.
 *
 * @since 1.10.0
 */
public class ShiroFilterConfiguration {

    private boolean filterOncePerRequest = false;

    private boolean staticSecurityManagerEnabled = false;

    /**
     * Returns {@code true} if the filter should only execute once per request. If set to {@code false} the filter
     * will execute each time it is invoked.
     * @return {@code true} if this filter should only execute once per request.
     */
    public boolean isFilterOncePerRequest() {
        return filterOncePerRequest;
    }

    /**
     * Sets whether the filter executes once per request or for every invocation of the filter. It is recommended
     * to leave this disabled if you are using a {@link javax.servlet.RequestDispatcher RequestDispatcher} to forward
     * or include request (JSP tags, programmatically, or via a framework).
     *
     * @param filterOncePerRequest Whether this filter executes once per request.
     */
    public void setFilterOncePerRequest(boolean filterOncePerRequest) {
        this.filterOncePerRequest = filterOncePerRequest;
    }

    /**
     * Returns {@code true} if the constructed {@link SecurityManager SecurityManager} associated with the filter
     * should be bound to static memory (via
     * {@code SecurityUtils.}{@link SecurityUtils#setSecurityManager(org.apache.shiro.mgt.SecurityManager) setSecurityManager}),
     * {@code false} otherwise.
     * <p/>
     * The default value is {@code false}.
     * <p/>
     *
     * @return {@code true} if the constructed {@link SecurityManager SecurityManager} associated with the filter should be bound
     *         to static memory (via {@code SecurityUtils.}{@link SecurityUtils#setSecurityManager(org.apache.shiro.mgt.SecurityManager) setSecurityManager}),
     *         {@code false} otherwise.
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-287">SHIRO-287</a>
     */
    public boolean isStaticSecurityManagerEnabled() {
        return staticSecurityManagerEnabled;
    }

    /**
     * Sets if the constructed {@link SecurityManager SecurityManager} associated with the filter should be bound
     * to static memory (via {@code SecurityUtils.}{@link SecurityUtils#setSecurityManager(org.apache.shiro.mgt.SecurityManager) setSecurityManager}).
     * <p/>
     * The default value is {@code false}.
     *
     * @param staticSecurityManagerEnabled if the constructed {@link SecurityManager SecurityManager} associated with the filter
     *                                       should be bound to static memory (via
     *                                       {@code SecurityUtils.}{@link SecurityUtils#setSecurityManager(org.apache.shiro.mgt.SecurityManager) setSecurityManager}).
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-287">SHIRO-287</a>
     */
    public ShiroFilterConfiguration setStaticSecurityManagerEnabled(boolean staticSecurityManagerEnabled) {
        this.staticSecurityManagerEnabled = staticSecurityManagerEnabled;
        return this;
    }
}
