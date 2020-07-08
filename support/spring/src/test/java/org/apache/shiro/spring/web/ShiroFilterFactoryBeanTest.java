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
package org.apache.shiro.spring.web;

import org.apache.shiro.web.filter.InvalidRequestFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.NamedFilterList;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Unit tests for the {@link ShiroFilterFactoryBean} implementation.
 *
 * @since 1.0
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations = {"/org/apache/shiro/spring/web/ShiroFilterFactoryBeanTest.xml"})
public class ShiroFilterFactoryBeanTest {

    @Test
    public void testFilterDefinition() {

        ClassPathXmlApplicationContext context =
                new ClassPathXmlApplicationContext("org/apache/shiro/spring/web/ShiroFilterFactoryBeanTest.xml");

        AbstractShiroFilter shiroFilter = (AbstractShiroFilter) context.getBean("shiroFilter");

        PathMatchingFilterChainResolver resolver = (PathMatchingFilterChainResolver) shiroFilter.getFilterChainResolver();
        DefaultFilterChainManager fcManager = (DefaultFilterChainManager) resolver.getFilterChainManager();
        NamedFilterList chain = fcManager.getChain("/test");
        assertNotNull(chain);
        assertEquals(chain.size(), 3);
        Filter[] filters = new Filter[chain.size()];
        filters = chain.toArray(filters);
        assertTrue(filters[0] instanceof InvalidRequestFilter); // global filter
        assertTrue(filters[1] instanceof DummyFilter);
        assertTrue(filters[2] instanceof FormAuthenticationFilter);
    }

    /**
     * Verifies fix for <a href="https://issues.apache.org/jira/browse/SHIRO-167">SHIRO-167</a>
     *
     * @throws Exception if there is any unexpected error
     */
    @Test
    public void testFilterDefinitionWithInit() throws Exception {

        ClassPathXmlApplicationContext context =
                new ClassPathXmlApplicationContext("org/apache/shiro/spring/web/ShiroFilterFactoryBeanTest.xml");

        AbstractShiroFilter shiroFilter = (AbstractShiroFilter) context.getBean("shiroFilter");

        FilterConfig mockFilterConfig = createNiceMock(FilterConfig.class);
        ServletContext mockServletContext = createNiceMock(ServletContext.class);
        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext).anyTimes();
        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        expect(mockRequest.getContextPath()).andReturn("/").anyTimes();
        expect(mockRequest.getRequestURI()).andReturn("/").anyTimes();
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        replay(mockFilterConfig);
        replay(mockServletContext);
        shiroFilter.init(mockFilterConfig);
        verify(mockServletContext);
        verify(mockFilterConfig);

        FilterChain filterChain = new FilterChain() {
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                assertNotNull(request.getSession());
                //this line asserts the fix for the user-reported issue:
                assertNotNull(request.getSession().getServletContext());
            }
        };

        replay(mockRequest);
        replay(mockResponse);

        shiroFilter.doFilter(mockRequest, mockResponse, filterChain);

        verify(mockResponse);
        verify(mockRequest);
    }
}
