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
package org.apache.shiro.web.servlet

import org.apache.shiro.web.config.ShiroFilterConfiguration
import org.apache.shiro.web.env.EnvironmentLoader
import org.apache.shiro.web.env.WebEnvironment
import org.apache.shiro.web.filter.mgt.FilterChainResolver
import org.apache.shiro.web.mgt.WebSecurityManager
import org.junit.jupiter.api.Test

import javax.servlet.FilterConfig
import javax.servlet.ServletContext

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.sameInstance
import static org.mockito.ArgumentMatchers.eq
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

/**
 * Unit tests for {@link ShiroFilter}.
 */
class ShiroFilterTest {

    @Test
    void testInit() {

        def filterConfig = mock(FilterConfig)
        def servletContext = mock(ServletContext)
        def shiroFilterConfig = mock(ShiroFilterConfiguration)
        def webEnvironment = mock(WebEnvironment)
        def webSecurityManager = mock(WebSecurityManager)
        def filterChainResolver = mock(FilterChainResolver)

        when(filterConfig.servletContext).thenReturn(servletContext)
        when(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).thenReturn null
        when(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).thenReturn webEnvironment
        when(shiroFilterConfig.filterOncePerRequest).thenReturn true
        when(shiroFilterConfig.staticSecurityManagerEnabled).thenReturn false
        when(webEnvironment.shiroFilterConfiguration).thenReturn shiroFilterConfig
        when(webEnvironment.webSecurityManager).thenReturn webSecurityManager
        when(webEnvironment.filterChainResolver).thenReturn filterChainResolver

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertThat filter.securityManager, sameInstance(webSecurityManager)
        assertThat filter.filterChainResolver, sameInstance(filterChainResolver)
        assertThat("expected filter.isFilterOncePerRequest() to return true", filter.isFilterOncePerRequest())
        assertThat("expected filter.isStaticSecurityManagerEnabled() to return false", !filter.isStaticSecurityManagerEnabled())
    }

    @Test
    void configStaticSecManager_initParm() {

        def filterConfig = mock(FilterConfig)
        def servletContext = mock(ServletContext)
        def shiroFilterConfig = mock(ShiroFilterConfiguration)
        def webEnvironment = mock(WebEnvironment)
        def webSecurityManager = mock(WebSecurityManager)
        def filterChainResolver = mock(FilterChainResolver)

        when(filterConfig.servletContext).thenReturn(servletContext)
        when(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).thenReturn "true"
        when(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).thenReturn webEnvironment
        when(shiroFilterConfig.filterOncePerRequest).thenReturn false
        when(shiroFilterConfig.staticSecurityManagerEnabled).thenReturn false
        when(webEnvironment.shiroFilterConfiguration).thenReturn shiroFilterConfig
        when(webEnvironment.webSecurityManager).thenReturn webSecurityManager
        when(webEnvironment.filterChainResolver).thenReturn filterChainResolver

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertThat("expected filter.isStaticSecurityManagerEnabled() to return true", filter.isStaticSecurityManagerEnabled())
    }

    @Test
    void configStaticSecManager_config() {

        def filterConfig = mock(FilterConfig)
        def servletContext = mock(ServletContext)
        def shiroFilterConfig = mock(ShiroFilterConfiguration)
        def webEnvironment = mock(WebEnvironment)
        def webSecurityManager = mock(WebSecurityManager)
        def filterChainResolver = mock(FilterChainResolver)

        when(filterConfig.servletContext).thenReturn(servletContext)
        when(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).thenReturn null
        when(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).thenReturn webEnvironment
        when(shiroFilterConfig.filterOncePerRequest).thenReturn false
        when(shiroFilterConfig.staticSecurityManagerEnabled).thenReturn true
        when(webEnvironment.shiroFilterConfiguration).thenReturn shiroFilterConfig
        when(webEnvironment.webSecurityManager).thenReturn webSecurityManager
        when(webEnvironment.filterChainResolver).thenReturn filterChainResolver

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertThat("expected filter.isStaticSecurityManagerEnabled() to return true", filter.isStaticSecurityManagerEnabled())
    }
}
