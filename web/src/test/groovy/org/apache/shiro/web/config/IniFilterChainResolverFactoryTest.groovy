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
package org.apache.shiro.web.config

import org.apache.shiro.web.filter.InvalidRequestFilter
import org.apache.shiro.web.filter.mgt.DefaultFilter
import org.hamcrest.Matchers

import javax.servlet.Filter
import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.apache.shiro.config.Ini
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter
import org.apache.shiro.web.filter.authz.SslFilter
import org.apache.shiro.web.filter.mgt.FilterChainResolver
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import static org.hamcrest.MatcherAssert.assertThat

/**
 * Unit tests for the {@link IniFilterChainResolverFactory} implementation.
 *
 * @since 1.2
 */
class IniFilterChainResolverFactoryTest {

    private IniFilterChainResolverFactory factory;

    protected FilterConfig createNiceMockFilterConfig() {
        FilterConfig mock = createNiceMock(FilterConfig)
        ServletContext mockServletContext = createNiceMock(ServletContext)
        expect(mock.servletContext).andReturn(mockServletContext)
        return mock
    }

    @Before
    void setUp() {
        this.factory = new IniFilterChainResolverFactory()
    }

    @Test
    void testNewInstance() {
        assertNull factory.filterConfig
        factory.filterConfig = null
        assertNull factory.filterConfig
        assertThat factory.globalFilters, Matchers.contains(DefaultFilter.invalidRequest.name())
    }

    @Test
    void testGetInstanceNoIni() {
        assertNotNull factory.getInstance()
    }

    @Test
    void testNewInstanceWithIni() {
        Ini ini = new Ini()
        ini.load("""
        [urls]
        /index.html = anon
        """)
        factory = new IniFilterChainResolverFactory(ini)
        FilterChainResolver resolver = factory.getInstance()
        assertNotNull resolver
        assertThat resolver.filterChainManager.globalFilterNames, Matchers.contains(DefaultFilter.invalidRequest.name())
    }

    @Test
    void testGetFiltersWithNullOrEmptySection() {
        Map<String, Filter> filters = factory.getFilters(null, null);
        assertNull(filters);
    }

    @Test
    void testCreateChainsWithNullUrlsSection() {
        //should do nothing (return immediately, no exceptions):
        factory.createChains(null, null);
    }

    @Test
    void testNewInstanceWithNonFilter() {
        Ini ini = new Ini()
        ini.load("""
        [filters]
        # any non filter will do:
        test = org.apache.shiro.web.servlet.SimpleCookie
        [urls]
        /index.html = anon
        """)
        factory = new IniFilterChainResolverFactory(ini)
        assertNotNull factory.getInstance()
    }

    @Test
    void testNewInstanceWithFilterConfig() {
        Ini ini = new Ini()
        ini.load("""
        [urls]
        /index.html = anon
        """)
        factory = new IniFilterChainResolverFactory(ini)
        FilterConfig config = createNiceMockFilterConfig()
        factory.setFilterConfig(config)
        
        replay config
        
        FilterChainResolver resolver = factory.getInstance();
        
        assertNotNull resolver
        
        verify config
    }

    //asserts SHIRO-306
    @Test
    void testGetFilters() {
        def extractedFilters = factory.getFilters(null, null)
        assertNull extractedFilters
    }

    //asserts SHIRO-306
    @Test
    void testGetFiltersWithoutSectionWithDefaults() {
        def factory = new IniFilterChainResolverFactory()

        def defaults = ['filter': new FormAuthenticationFilter()]

        def extractedFilters = factory.getFilters(null, defaults)
        
        assertNotNull extractedFilters
        assertEquals 1, extractedFilters.size()
        assertTrue extractedFilters['filter'] instanceof FormAuthenticationFilter
    }

    //asserts SHIRO-306
    @Test
    void testGetFiltersWithSectionWithoutDefaults() {
        def factory = new IniFilterChainResolverFactory()

        def section = ['filter': FormAuthenticationFilter.class.name]

        def extractedFilters = factory.getFilters(section, null)

        assertNotNull extractedFilters
        assertEquals 1, extractedFilters.size()
        assertTrue extractedFilters['filter'] instanceof FormAuthenticationFilter
    }

    //asserts SHIRO-306
    @Test
    void testGetFiltersWithSectionAndDefaults() {
        def factory = new IniFilterChainResolverFactory()

        def section = ['filtersSectionFilter': SslFilter.class.name]

        def defaults = ['mainSectionFilter': new FormAuthenticationFilter()]

        def extractedFilters = factory.getFilters(section, defaults)

        assertNotNull extractedFilters
        assertEquals 2, extractedFilters.size()
        assertTrue extractedFilters['filtersSectionFilter'] instanceof SslFilter
        assertTrue extractedFilters['mainSectionFilter'] instanceof FormAuthenticationFilter
    }

    @Test
    void testConfigureInvalidRequestFilter() {
        Ini ini = new Ini()
        ini.load("""
        [main]
        invalidRequest.blockBackslash = false
        [urls]
        /index.html = anon
        """)
        factory = new IniFilterChainResolverFactory(ini)
        FilterChainResolver resolver = factory.getInstance()
        assertNotNull resolver

        def invalidRequestFilter = resolver.filterChainManager.getChain("/index.html").get(0) // this will be the invalidRequest filter

        assertThat(invalidRequestFilter, Matchers.instanceOf(InvalidRequestFilter))
        assertThat("blockSemicolon should be faluse", invalidRequestFilter.blockBackslash)
    }
}
