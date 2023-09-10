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
package org.apache.shiro.web.filter.mgt;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.web.WebTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver}.
 *
 * @since 1.0
 */
public class PathMatchingFilterChainResolverTest extends WebTest {

    private PathMatchingFilterChainResolver resolver;

    @BeforeEach
    public void setUp() {
        resolver = new PathMatchingFilterChainResolver();
    }

    @Test
    void testNewInstance() {
        assertNotNull(resolver.getPathMatcher());
        assertTrue(resolver.getPathMatcher() instanceof AntPathMatcher);
        assertNotNull(resolver.getFilterChainManager());
        assertTrue(resolver.getFilterChainManager() instanceof DefaultFilterChainManager);
    }

    @Test
    void testNewInstanceWithFilterConfig() {
        FilterConfig mock = createNiceMockFilterConfig();
        resolver = new PathMatchingFilterChainResolver(mock);
        assertNotNull(resolver.getPathMatcher());
        assertTrue(resolver.getPathMatcher() instanceof AntPathMatcher);
        assertNotNull(resolver.getFilterChainManager());
        assertTrue(resolver.getFilterChainManager() instanceof DefaultFilterChainManager);
        assertEquals(((DefaultFilterChainManager) resolver.getFilterChainManager()).getFilterConfig(), mock);
    }

    @Test
    void testSetters() {
        resolver.setPathMatcher(new AntPathMatcher());
        assertNotNull(resolver.getPathMatcher());
        assertTrue(resolver.getPathMatcher() instanceof AntPathMatcher);
        resolver.setFilterChainManager(new DefaultFilterChainManager());
        assertNotNull(resolver.getFilterChainManager());
        assertTrue(resolver.getFilterChainManager() instanceof DefaultFilterChainManager);
    }

    @Test
    void testGetChainsWithoutChains() {
        ServletRequest request = mock(HttpServletRequest.class);
        ServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNull(resolved);
    }

    @Test
    void testGetChainsWithMatch() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/index.html", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/index.html");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    @Test
    void testPathTraversalWithDot() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/index.html", "authcBasic");

        when(request.getServletPath()).thenReturn("/");
        when(request.getPathInfo()).thenReturn("./index.html");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    @Test
    void testPathTraversalWithDotDot() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/index.html", "authcBasic");
        when(request.getServletPath()).thenReturn("/public/");
        when(request.getPathInfo()).thenReturn("../index.html");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    @Test
    void testGetChainsWithoutMatch() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/index.html", "authcBasic");

        when(request.getServletPath()).thenReturn("/");
        when(request.getPathInfo()).thenReturn(null);

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNull(resolved);
        verify(request).getServletPath();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testGetChain() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/resource/book", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/book");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-742">SHIRO-742<a/>.
     */
    @Test
    void testGetChainEqualUrlSeparator() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/", "authcBasic");

        when(request.getServletPath()).thenReturn("/");
        when(request.getPathInfo()).thenReturn(null);

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testGetChainEndWithUrlSeparator() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/resource/book", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/book");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testGetChainEndWithMultiUrlSeparator() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/resource/book", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/book//");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    @Test
    void testMultipleChainsPathEndsWithSlash() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //Define the filter chain
        resolver.getFilterChainManager().addToChain("/login", "authc");
        resolver.getFilterChainManager().addToChain("/resource/*", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertThat(resolved, notNullValue());
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-825">SHIRO-825<a/>.
     */
    @Test
    void testGetChainWhenPathEndsWithSlash() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/resource/*/book", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/123/book/");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-825">SHIRO-825<a/>.
     */
    @Test
    void testGetChainWhenPathDoesNotEndWithSlash() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        //ensure at least one chain is defined:
        resolver.getFilterChainManager().addToChain("/resource/*/book", "authcBasic");

        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/resource/123/book");

        FilterChain resolved = resolver.getChain(request, response, chain);
        assertNotNull(resolved);
        verify(request).getServletPath();
    }
}
