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
import org.apache.shiro.SecurityUtils
import org.apache.shiro.UnavailableSecurityManagerException
import org.apache.shiro.web.mgt.WebSecurityManager
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link AbstractShiroFilter} implementation.
 */
class AbstractShiroFilterTest {

    @Test
    void testInit() {

        SecurityUtils.securityManager = null

        def securityManager = createStrictMock(WebSecurityManager)
        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.servletContext).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn null

        replay securityManager, filterConfig, servletContext

        AbstractShiroFilter filter = new AbstractShiroFilter() {}
        filter.securityManager = securityManager

        filter.init(filterConfig)

        try {
            SecurityUtils.getSecurityManager()
            fail "AbstractShiroFilter initialization should not have resulted in a static SecurityManager reference."
        } catch (UnavailableSecurityManagerException expected) {
        }

        verify securityManager, filterConfig, servletContext
    }

    @Test
    void testInitWithStaticReference() {

        SecurityUtils.securityManager = null

        def securityManager = createStrictMock(WebSecurityManager)
        def filterConfig = createStrictMock(FilterConfig)
        def servletContext = createStrictMock(ServletContext)

        expect(filterConfig.servletContext).andReturn servletContext
        expect(filterConfig.getInitParameter(eq(AbstractShiroFilter.STATIC_INIT_PARAM_NAME))).andReturn "true"

        replay securityManager, filterConfig, servletContext

        AbstractShiroFilter filter = new AbstractShiroFilter(){}
        filter.securityManager = securityManager

        try {
            filter.init(filterConfig)

            assertSame securityManager, SecurityUtils.securityManager

            verify securityManager, filterConfig, servletContext
        } finally {
            SecurityUtils.securityManager = null
        }
    }

}
