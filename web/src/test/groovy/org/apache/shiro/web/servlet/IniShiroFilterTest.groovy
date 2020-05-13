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

import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import javax.servlet.ServletException
import org.apache.shiro.lang.io.ResourceUtils
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link IniShiroFilter} implementation.
 */
class IniShiroFilterTest {

    @Test
    void testDefaultWebInfConfig() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        InputStream inputStream = ResourceUtils.getInputStreamForPath("classpath:IniShiroFilterTest.ini")
        assertNotNull inputStream

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn null
        //simulate the servlet context resource of /WEB-INF/shiro.ini to be our test file above:
        expect(servletContext.getResourceAsStream(eq(IniShiroFilter.DEFAULT_WEB_INI_RESOURCE_PATH))).andReturn(inputStream)

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

    @Test
    void testResourceConfig() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn "classpath:IniShiroFilterTest.ini"

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

    @Test
    void testResourceConfigWithoutResource() {
        def filterConfig = createMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)
        def nonExistentResource = "/WEB-INF/foo.ini"

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn nonExistentResource
        expect(servletContext.getResourceAsStream(eq(nonExistentResource))).andReturn(null)

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        try {
            filter.init(filterConfig)
            fail "Filter init should have failed due to specified nonexisting resource path."
        } catch (ServletException expected) {
        }

        verify filterConfig, servletContext
    }

    @Test
    void testDefaultClasspathConfig() {

        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_INIT_PARAM_NAME)).andReturn null
        expect(filterConfig.getInitParameter(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME)).andReturn null
        expect(servletContext.getResourceAsStream(IniShiroFilter.DEFAULT_WEB_INI_RESOURCE_PATH)).andReturn null

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

    @Test
    void testSimpleConfig() {
        def config = """
        [filters]
        authc.successUrl = /index.jsp
        """
        def filterConfig = createMock(FilterConfig)
        def servletContext = createMock(ServletContext)

        expect(filterConfig.getServletContext()).andReturn(servletContext).anyTimes()
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_INIT_PARAM_NAME))).andReturn config
        expect(filterConfig.getInitParameter(eq(IniShiroFilter.CONFIG_PATH_INIT_PARAM_NAME))).andReturn null

        replay filterConfig, servletContext

        IniShiroFilter filter = new IniShiroFilter()
        filter.init(filterConfig)

        verify filterConfig, servletContext
    }

}
