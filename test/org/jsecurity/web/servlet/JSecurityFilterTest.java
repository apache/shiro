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
package org.jsecurity.web.servlet;

import static org.easymock.EasyMock.*;
import org.jsecurity.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class JSecurityFilterTest {

    private static final String FILTER_NAME = "JSecurityFilter";

    private JSecurityFilter filter;
    private FilterConfig mockFilterConfig;
    private ServletContext mockServletContext;
    private FilterChain mockFilterChain;

    @Before
    public void setUp() {
        ThreadContext.clear();
    }

    @After
    public void tearDown() {
        ThreadContext.clear();
    }

    protected void setUp(String config) {
        mockFilterConfig = createMock(FilterConfig.class);
        mockServletContext = createMock(ServletContext.class);
        mockFilterChain = createNiceMock(FilterChain.class);

        expect(mockFilterConfig.getServletContext()).andReturn(mockServletContext);
        expect(mockFilterConfig.getInitParameter(JSecurityFilter.CONFIG_CLASS_NAME_INIT_PARAM_NAME)).andReturn(null).once();
        expect(mockFilterConfig.getInitParameter(JSecurityFilter.CONFIG_INIT_PARAM_NAME)).andReturn(config).once();
        expect(mockFilterConfig.getInitParameter(JSecurityFilter.CONFIG_URL_INIT_PARAM_NAME)).andReturn(null).once();
    }

    protected void replayAndVerify() throws Exception {
        replay(mockServletContext);
        replay(mockFilterConfig);

        this.filter = new JSecurityFilter();
        this.filter.init(mockFilterConfig);

        verify(mockFilterConfig);
        verify(mockServletContext);
    }


    @Test
    public void testDefaultConfig() throws Exception {
        setUp(null);
        replayAndVerify();
    }

    @Test
    public void testSimpleConfig() throws Exception {
        setUp("[filters]\n" +
                "authc.successUrl = /index.jsp");
        replayAndVerify();
    }

    protected void testRequest(String config) throws Exception {
        setUp(config);
        expect(mockFilterConfig.getFilterName()).andReturn(FILTER_NAME);
        replay(mockServletContext);
        replay(mockFilterConfig);

        filter = new JSecurityFilter();
        filter.init(mockFilterConfig);

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        mockRequest.setAttribute(FILTER_NAME + JSecurityFilter.ALREADY_FILTERED_SUFFIX, Boolean.TRUE);

        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        replay(mockRequest);

        filter.doFilter(mockRequest, mockResponse, mockFilterChain);

        verify(mockRequest);
        verify(mockFilterConfig);
        verify(mockServletContext);
    }

    /**
     * Along with {@link #testSimpleRequestJSecuritySessionMode()}, this method asserts that
     * <a href="https://issues.apache.org/jira/browse/JSEC-33">JSEC-33</a> is resolved.
     *
     * @throws Exception if an error occurs
     */
    @Test
    public void testSimpleRequest() throws Exception {
        testRequest(null);
    }

    /**
     * Along with {@link #testSimpleRequest()}, this method asserts that
     * <a href="https://issues.apache.org/jira/browse/JSEC-33">JSEC-33</a> is resolved.
     *
     * @throws Exception if an error occurs
     */
    @Test
    public void testSimpleRequestJSecuritySessionMode() throws Exception {
        String config = "[main]\n" +
                "securityManager.sessionMode = jsecurity";
        testRequest(config);

    }
}
