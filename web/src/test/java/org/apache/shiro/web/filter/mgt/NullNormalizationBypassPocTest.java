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

import org.apache.shiro.web.util.WebUtils;
import org.junit.jupiter.api.Test;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Reproduces the filter chain bypass caused by null path normalization and asserts
 * the fix fails closed.
 *
 * <p>Before the fix, {@link WebUtils#getPathWithinApplication(jakarta.servlet.http.HttpServletRequest)}
 * returned {@code null} when {@code normalize()} failed (e.g. path traversal above root, like
 * {@code servletPath="/"} + {@code pathInfo="../"}). The {@code null} propagated through
 * {@link PathMatchingFilterChainResolver#getChain}, which matched no patterns and returned
 * {@code null}, causing {@code AbstractShiroFilter} to execute the original, unfiltered
 * container chain.</p>
 *
 * <p>After the fix, normalization failure throws {@link IllegalStateException}, so the
 * request fails closed instead of being served without any Shiro filtering.</p>
 */
public class NullNormalizationBypassPocTest {

    @Test
    void getPathWithinApplicationThrowsForTraversalFromRoot() {
        HttpServletRequest request = request("/", "../");

        assertThrows(IllegalStateException.class,
                () -> WebUtils.getPathWithinApplication(request));
    }

    @Test
    void getPathWithinApplicationThrowsForTraversalAboveRoot() {
        HttpServletRequest request = request("/app", "/../../");

        assertThrows(IllegalStateException.class,
                () -> WebUtils.getPathWithinApplication(request));
    }

    @Test
    void resolverFailsClosedOnTraversalRequest() {
        PathMatchingFilterChainResolver resolver = resolverWithCatchAllChain();
        HttpServletRequest request = request("/", "../");
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain originalChain = mock(FilterChain.class);

        // Before the fix this returned null (no pattern matched), which made
        // AbstractShiroFilter fall back to the unfiltered original chain.
        assertThrows(IllegalStateException.class,
                () -> resolver.getChain(request, response, originalChain));
    }

    @Test
    void resolverStillResolvesNormalRequests() {
        PathMatchingFilterChainResolver resolver = resolverWithCatchAllChain();
        HttpServletRequest request = request("/", "resource/menus");
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain originalChain = mock(FilterChain.class);

        assertNotNull(resolver.getChain(request, response, originalChain));
    }

    private static PathMatchingFilterChainResolver resolverWithCatchAllChain() {
        PathMatchingFilterChainResolver resolver = new PathMatchingFilterChainResolver();
        resolver.getFilterChainManager().createChain("/**", "anon");
        return resolver;
    }

    private static HttpServletRequest request(String servletPath, String pathInfo) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn(servletPath);
        when(request.getPathInfo()).thenReturn(pathInfo);
        return request;
    }
}
