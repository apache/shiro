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
package org.apache.shiro.web.servlet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link OncePerRequestFilter} implementation.
 *
 * @since 1.2
 */
public class OncePerRequestFilterTest {

    private static final String NAME = "oncePerRequestFilter";
    private static final String ATTR_NAME = NAME + OncePerRequestFilter.ALREADY_FILTERED_SUFFIX;

    private CountingOncePerRequestFilter filter;
    private FilterChain chain;
    private ServletRequest request;
    private ServletResponse response;

    @BeforeEach
    public void setUp() {
        filter = createTestInstance();
        chain = mock(FilterChain.class);
        request = mock(ServletRequest.class);
        response = mock(ServletResponse.class);
    }

    private CountingOncePerRequestFilter createTestInstance() {
        return new CountingOncePerRequestFilter();
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    void testEnabled() throws IOException, ServletException {
        when(request.getAttribute(ATTR_NAME)).thenReturn(null);

        filter.doFilter(request, response, chain);

        assertThat(filter.filterCount).as("Filter should have executed").isEqualTo(1);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    void testDisabled() throws IOException, ServletException {
        //test disabled
        filter.setEnabled(false);

        when(request.getAttribute(ATTR_NAME)).thenReturn(null);

        filter.doFilter(request, response, chain);

        assertThat(filter.filterCount).as("Filter should NOT have executed").isEqualTo(0);
    }

    @Test
    void testFilterOncePerRequest() throws IOException, ServletException {
        filter.setFilterOncePerRequest(false);

        when(request.getAttribute(ATTR_NAME)).thenReturn(null, true);

        filter.doFilter(request, response, chain);
        filter.doFilter(request, response, chain);

        assertThat(filter.filterCount).as("Filter should have executed twice").isEqualTo(2);
    }

    static class CountingOncePerRequestFilter extends OncePerRequestFilter {

        private int filterCount;

        CountingOncePerRequestFilter() {
            this.setName(NAME);
        }

        @Override
        protected void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) {
            filterCount++;
        }
    }
}
