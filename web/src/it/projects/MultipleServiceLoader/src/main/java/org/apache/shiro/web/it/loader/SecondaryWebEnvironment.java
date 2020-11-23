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

package org.apache.shiro.web.it.loader;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

public class SecondaryWebEnvironment implements WebEnvironment {
    @Override
    public FilterChainResolver getFilterChainResolver() {
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.web.it.loader.SecondaryWebEnvironment::getFilterChainResolver].");
    }

    @Override
    public javax.servlet.ServletContext getServletContext() {
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.web.it.loader.SecondaryWebEnvironment::getServletContext].");
    }

    @Override
    public WebSecurityManager getWebSecurityManager() {
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.web.it.loader.SecondaryWebEnvironment::getWebSecurityManager].");
    }

    @Override
    public SecurityManager getSecurityManager() {
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.web.it.loader.SecondaryWebEnvironment::getSecurityManager].");
    }
}
