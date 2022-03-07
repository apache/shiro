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
package org.apache.shiro.web.filter.mgt

import org.apache.shiro.config.ConfigurationException
import org.apache.shiro.web.filter.authz.SslFilter
import org.apache.shiro.web.servlet.ShiroFilter
import org.hamcrest.Matchers

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletContext
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import static org.hamcrest.MatcherAssert.assertThat

/**
 * Unit tests for the {@link DefaultFilterChainManager} implementation.
 */
class DefaultFilterChainManagerTest {

    DefaultFilterChainManager manager;

    @Before
    void setUp() {
        this.manager = new DefaultFilterChainManager();
    }

    //SHIRO-205
    @Test
    void testToNameConfigPairNoBrackets() {
        def token = "foo"

        String[] pair = manager.toNameConfigPair(token);

        assertNotNull pair
        assertEquals 2, pair.length
        assertEquals "foo", pair[0]
        assertNull pair[1]
    }

    //SHIRO-205
    @Test
    void testToNameConfigPairWithEmptyBrackets() {
        def token = "foo[]"

        String[] pair = manager.toNameConfigPair(token);

        assertNotNull pair
        assertEquals 2, pair.length
        assertEquals "foo", pair[0]
        assertNull pair[1]
    }

    //SHIRO-205
    @Test
    void testToNameConfigPairWithPopulatedBrackets() {
        def token = "foo[bar, baz]"

        String[] pair = manager.toNameConfigPair(token);

        assertNotNull pair
        assertEquals 2, pair.length
        assertEquals "foo", pair[0]
        assertEquals "bar, baz", pair[1]
    }

    //SHIRO-205 - asserts backwards compatibility before SHIRO-205 was implemented:
    @Test
    void testToNameConfigPairWithNestedQuotesInBrackets() {
        def token = 'roles["guest, admin"]'

        String[] pair = manager.toNameConfigPair(token);

        assertNotNull pair
        assertEquals 2, pair.length
        assertEquals "roles", pair[0]
        assertEquals "guest, admin", pair[1]
    }

    //SHIRO-205 - asserts backwards compatibility before SHIRO-205 was implemented:
    //@since 1.2.2
    @Test
    void testToNameConfigPairWithIndividualNestedQuotesInBrackets() {
        def token = 'roles["guest", "admin"]'

        String[] pair = manager.toNameConfigPair(token);

        assertNotNull pair
        assertEquals 2, pair.length
        assertEquals "roles", pair[0]
        assertEquals '"guest", "admin"', pair[1]
    }
    
    //SHIRO-205
    @Test
    void testFilterChainConfigWithNestedCommas() {
        def chain = "a, b[c], d[e, f], g[h, i, j], k"

        String[] tokens = manager.splitChainDefinition(chain);
        
        assertNotNull tokens
        assertEquals 5, tokens.length
        assertEquals "a", tokens[0]
        assertEquals "b[c]", tokens[1]
        assertEquals "d[e, f]", tokens[2]
        assertEquals "g[h, i, j]", tokens[3]
        assertEquals "k", tokens[4]
    }

    //SHIRO-205
    @Test
    void testFilterChainConfigWithNestedQuotedCommas() {
        def chain = "a, b[c], d[e, f], g[h, i, j], k"

        String[] tokens = manager.splitChainDefinition(chain);

        assertNotNull tokens
        assertEquals 5, tokens.length
        assertEquals "a", tokens[0]
        assertEquals "b[c]", tokens[1]
        assertEquals "d[e, f]", tokens[2]
        assertEquals "g[h, i, j]", tokens[3]
        assertEquals "k", tokens[4]
    }

    @Test
    void testNewInstanceDefaultFilters() {
        for (DefaultFilter defaultFilter : DefaultFilter.values()) {
            assertNotNull(manager.getFilter(defaultFilter.name()));
        }
        assertFalse(manager.hasChains());
    }

    protected FilterConfig createNiceMockFilterConfig() {
        FilterConfig mock = createNiceMock(FilterConfig.class);
        ServletContext mockServletContext = createNiceMock(ServletContext.class);
        expect(mock.getServletContext()).andReturn(mockServletContext);
        return mock;
    }

    @Test
    void testNewInstanceWithFilterConfig() {
        FilterConfig mock = createNiceMockFilterConfig();
        replay(mock);
        this.manager = new DefaultFilterChainManager(mock);
        for (DefaultFilter defaultFilter : DefaultFilter.values()) {
            assertNotNull(manager.getFilter(defaultFilter.name()));
        }
        assertFalse(manager.hasChains());
        verify(mock);
    }

    @Test
    void testCreateChain() {
        try {
            manager.createChain(null, null);
        } catch (NullPointerException expected) {
        }
        try {
            manager.createChain("test", null);
        } catch (NullPointerException expected) {
        }

        manager.createChain("test", "authc, roles[manager], perms[\"user:read,write:12345\"");

        assertTrue(manager.hasChains());

        Set<String> chainNames = manager.getChainNames();
        assertNotNull(chainNames);
        assertEquals(1, chainNames.size());
        assertTrue(chainNames.contains("test"));

        Map<String, NamedFilterList> chains = manager.getFilterChains();
        assertEquals(1, chains.size());
        assertTrue(chains.containsKey("test"));
        manager.setFilterChains(chains);

        NamedFilterList chain = manager.getChain("test");
        assertNotNull(chain);

        Filter filter = chain.get(0);
        assertNotNull(filter);
        assertEquals(DefaultFilter.authc.getFilterClass(), filter.getClass());

        filter = chain.get(1);
        assertNotNull(filter);
        assertEquals(DefaultFilter.roles.getFilterClass(), filter.getClass());

        filter = chain.get(2);
        assertNotNull(filter);
        assertEquals(DefaultFilter.perms.getFilterClass(), filter.getClass());
    }

    @Test
    void testWithGlobalFilters() {
        DefaultFilterChainManager manager = new DefaultFilterChainManager()
        manager.setGlobalFilters(["invalidRequest", "port"])
        assertThat(manager.filterChains, Matchers.anEmptyMap())

        // add a chain
        manager.createChain("test", "authc, roles[manager], perms[\"user:read,write:12345\"")

        assertThat(manager.getChain("test"), Matchers.contains(
                Matchers.instanceOf(DefaultFilter.invalidRequest.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.port.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.authc.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.roles.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.perms.getFilterClass())
        ))

        // the  "default" chain doesn't exist until it is created
        assertThat(manager.getChain("/**"), Matchers.nullValue())
        // create it
        manager.createDefaultChain("/**")
        // verify it
        assertThat(manager.getChain("/**"), Matchers.contains(
                Matchers.instanceOf(DefaultFilter.invalidRequest.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.port.getFilterClass())
        ))
    }

    @Test
    void addDefaultChainWithSameName() {

        DefaultFilterChainManager manager = new DefaultFilterChainManager()
        manager.setGlobalFilters(["invalidRequest", "port"])

        // create a chain
        manager.createChain("test", "authc")

        // create the default chain with the same name
        manager.createDefaultChain("test")

        // since the "default" chain was created with the same name as an existing chain, we could end up adding the
        // global filters to the chain twice, test to verify it is only once
        assertThat(manager.getChain("test"), Matchers.contains(
                Matchers.instanceOf(DefaultFilter.invalidRequest.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.port.getFilterClass()),
                Matchers.instanceOf(DefaultFilter.authc.getFilterClass())
        ))

    }

    /**
     * Helps assert <a href="https://issues.apache.org/jira/browse/SHIRO-429">SHIRO-429</a>
     * @since 1.2.2
     */
    @Test
    void testCreateChainWithQuotedInstanceConfig() {

        manager.createChain("test", 'authc, perms["perm1", "perm2"]');

        assertTrue(manager.hasChains());

        Set<String> chainNames = manager.getChainNames();
        assertNotNull(chainNames);
        assertEquals(1, chainNames.size());
        assertTrue(chainNames.contains("test"));

        Map<String, NamedFilterList> chains = manager.getFilterChains();
        assertEquals(1, chains.size());
        assertTrue(chains.containsKey("test"));
        manager.setFilterChains(chains);

        NamedFilterList chain = manager.getChain("test");
        assertNotNull(chain);

        Filter filter = chain.get(0);
        assertNotNull(filter);
        assertEquals(DefaultFilter.authc.getFilterClass(), filter.getClass());

        filter = chain.get(1);
        assertNotNull(filter);
        assertEquals(DefaultFilter.perms.getFilterClass(), filter.getClass());
    }

    @Test
    void testBeanMethods() {
        Map<String, Filter> filters = manager.getFilters();
        assertEquals(filters.size(), DefaultFilter.values().length);
        manager.setFilters(filters);
    }

    @Test
    void testAddFilter() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);
        manager.addFilter("test", new SslFilter());
        Filter filter = manager.getFilter("test");
        assertNotNull(filter);
        assertEquals(SslFilter.class, filter.getClass());
        verify(mockFilterConfig);
    }

    @Test
    void testAddFilterNoInit() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        Filter mockFilter = createNiceMock(Filter.class);

        replay mockFilterConfig, mockFilter

        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        this.manager.addFilter("blah", mockFilter);

        assertNotNull this.manager.filters['blah']
        assertSame this.manager.filters['blah'], mockFilter

        verify mockFilterConfig, mockFilter
    }

    @Test
    void testAddFilterNoFilterConfig() {
        SslFilter filter = new SslFilter();
        manager.addFilter("test", filter);
        assertNotNull manager.filters['test']
        assertSame manager.filters['test'], filter
    }

    @Test
    void testAddToChain() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        manager.addFilter("testSsl", new SslFilter());
        manager.createChain("test", "anon");

        try {
            manager.addToChain("test", null);
            fail "Should have thrown an IllegalArgumentException"
        } catch (IllegalArgumentException expected) {
        }
        try {
            manager.addToChain(null, "testSsl");
            fail "Should have thrown an IllegalArgumentException"
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testAddToChainNotPathProcessor() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        manager.addFilter("nonPathProcessor", new ShiroFilter());
        manager.createChain("test", "nonPathProcessor");

        try {
            manager.addToChain("test", "nonPathProcessor", "dummyConfig");
            fail "Should have thrown a ConfigurationException"
        } catch (ConfigurationException expected) {
        }
    }

    @Test
    void testProxy() {
        FilterChain mock = createNiceMock(FilterChain.class);
        replay(mock);
        manager.createChain("test", "anon");
        this.manager.proxy(mock, "test");
        verify(mock);
    }

    @Test
    void testProxyNoChain() {
        FilterChain mock = createNiceMock(FilterChain.class);
        replay(mock);
        try {
            this.manager.proxy(mock, "blah");
            fail "Should have thrown an IllegalArgumentException"
        } catch (IllegalArgumentException expected) {
        }
        verify(mock);
    }

}
