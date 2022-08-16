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

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.apache.shiro.web.env.EnvironmentLoader
import org.apache.shiro.web.env.WebEnvironment
import org.apache.shiro.web.filter.mgt.FilterChainResolver
import org.apache.shiro.web.mgt.WebSecurityManager
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for {@link ShiroFilter}.
 */
class ShiroFilterTest {

    @Test
    void testInit() {

        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def shiroFilterConfig = createStrictMock(ShiroFilterConfiguration)
        def webEnvironment = createStrictMock(WebEnvironment)
        def webSecurityManager = createStrictMock(WebSecurityManager)
        def filterChainResolver = createStrictMock(FilterChainResolver)

        expect(filterConfig.servletContext).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).andReturn webEnvironment
        expect(shiroFilterConfig.filterOncePerRequest).andReturn true
        expect(shiroFilterConfig.staticSecurityManagerEnabled).andReturn false
        expect(webEnvironment.shiroFilterConfiguration).andReturn shiroFilterConfig
        expect(webEnvironment.webSecurityManager).andReturn webSecurityManager
        expect(webEnvironment.filterChainResolver).andReturn filterChainResolver

        replay filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertSame filter.securityManager, webSecurityManager
        assertSame filter.filterChainResolver, filterChainResolver
        assertTrue(filter.isFilterOncePerRequest())
        assertFalse(filter.isStaticSecurityManagerEnabled())

        verify filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig
    }

    @Test
    void configStaticSecManager_initParm() {

        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def shiroFilterConfig = createStrictMock(ShiroFilterConfiguration)
        def webEnvironment = createStrictMock(WebEnvironment)
        def webSecurityManager = createStrictMock(WebSecurityManager)
        def filterChainResolver = createStrictMock(FilterChainResolver)

        expect(filterConfig.servletContext).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn "true"
        expect(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).andReturn webEnvironment
        expect(shiroFilterConfig.filterOncePerRequest).andReturn false
        expect(shiroFilterConfig.staticSecurityManagerEnabled).andReturn false
        expect(webEnvironment.shiroFilterConfiguration).andReturn shiroFilterConfig
        expect(webEnvironment.webSecurityManager).andReturn webSecurityManager
        expect(webEnvironment.filterChainResolver).andReturn filterChainResolver

        replay filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertTrue(filter.isStaticSecurityManagerEnabled())
        verify filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig
    }

    @Test
    void configStaticSecManager_config() {

        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def shiroFilterConfig = createStrictMock(ShiroFilterConfiguration)
        def webEnvironment = createStrictMock(WebEnvironment)
        def webSecurityManager = createStrictMock(WebSecurityManager)
        def filterChainResolver = createStrictMock(FilterChainResolver)

        expect(filterConfig.servletContext).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(servletContext.getAttribute(eq(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY))).andReturn webEnvironment
        expect(shiroFilterConfig.filterOncePerRequest).andReturn false
        expect(shiroFilterConfig.staticSecurityManagerEnabled).andReturn true
        expect(webEnvironment.shiroFilterConfiguration).andReturn shiroFilterConfig
        expect(webEnvironment.webSecurityManager).andReturn webSecurityManager
        expect(webEnvironment.filterChainResolver).andReturn filterChainResolver

        replay filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig

        ShiroFilter filter = new ShiroFilter()

        filter.init(filterConfig)

        assertTrue(filter.isStaticSecurityManagerEnabled())
        verify filterConfig, servletContext, webEnvironment, webSecurityManager, filterChainResolver, shiroFilterConfig
    }
}
