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

import javax.servlet.Filter
import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.apache.shiro.config.Ini
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter
import org.apache.shiro.web.filter.authz.SslFilter
import org.apache.shiro.web.filter.mgt.FilterChainResolver
import static org.easymock.EasyMock.*

/**
 * Unit tests for the {@link IniFilterChainResolverFactory} implementation.
 *
 * @since 1.2
 */
class IniFilterChainResolverFactoryTest extends GroovyTestCase {

    private IniFilterChainResolverFactory factory;

    protected FilterConfig createNiceMockFilterConfig() {
        FilterConfig mock = createNiceMock(FilterConfig)
        ServletContext mockServletContext = createNiceMock(ServletContext)
        expect(mock.servletContext).andReturn(mockServletContext)
        return mock
    }

    void setUp() {
        this.factory = new IniFilterChainResolverFactory()
    }

    void testNewInstance() {
        assertNull factory.filterConfig
        factory.filterConfig = null
        assertNull factory.filterConfig
    }

    void testGetInstanceNoIni() {
        assertNotNull factory.getInstance()
    }

    void testNewInstanceWithIni() {
        Ini ini = new Ini()
        ini.load("""
        [urls]
        /index.html = anon
        """)
        factory = new IniFilterChainResolverFactory(ini)
        FilterChainResolver resolver = factory.getInstance()
        assertNotNull resolver
    }

    void testGetFiltersWithNullOrEmptySection() {
        Map<String, Filter> filters = factory.getFilters(null, null);
        assertNull(filters);
    }

    void testCreateChainsWithNullUrlsSection() {
        //should do nothing (return immediately, no exceptions):
        factory.createChains(null, null);
    }

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
    void testGetFilters() {
        def extractedFilters = factory.getFilters(null, null)
        assertNull extractedFilters
    }

    //asserts SHIRO-306
    void testGetFiltersWithoutSectionWithDefaults() {
        def factory = new IniFilterChainResolverFactory()

        def defaults = ['filter': new FormAuthenticationFilter()]

        def extractedFilters = factory.getFilters(null, defaults)
        
        assertNotNull extractedFilters
        assertEquals 1, extractedFilters.size()
        assertTrue extractedFilters['filter'] instanceof FormAuthenticationFilter
    }

    //asserts SHIRO-306
    void testGetFiltersWithSectionWithoutDefaults() {
        def factory = new IniFilterChainResolverFactory()

        def section = ['filter': FormAuthenticationFilter.class.name]

        def extractedFilters = factory.getFilters(section, null)

        assertNotNull extractedFilters
        assertEquals 1, extractedFilters.size()
        assertTrue extractedFilters['filter'] instanceof FormAuthenticationFilter
    }

    //asserts SHIRO-306
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
}
