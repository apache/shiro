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

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.web.filter.authz.SslFilter;
import org.apache.shiro.web.servlet.ShiroFilter;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.*;
import java.util.Map;
import java.util.Set;

/**
 * Test case for the {@link DefaultFilterChainManager} implementation.
 *
 * @since 1.0
 */
public class DefaultFilterChainManagerTest {

    DefaultFilterChainManager manager;

    @Before
    public void setUp() {
        this.manager = new DefaultFilterChainManager();
    }

    @Test
    public void testNewInstanceDefaultFilters() {
        for (DefaultFilterChainManager.DefaultFilter defaultFilter : DefaultFilterChainManager.DefaultFilter.values()) {
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
    public void testNewInstanceWithFilterConfig() {
        FilterConfig mock = createNiceMockFilterConfig();
        replay(mock);
        this.manager = new DefaultFilterChainManager(mock);
        for (DefaultFilterChainManager.DefaultFilter defaultFilter : DefaultFilterChainManager.DefaultFilter.values()) {
            assertNotNull(manager.getFilter(defaultFilter.name()));
        }
        assertFalse(manager.hasChains());
        verify(mock);
    }

    @Test
    public void testCreateChain() {
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
        assertEquals(DefaultFilterChainManager.DefaultFilter.authc.getFilterClass(), filter.getClass());

        filter = chain.get(1);
        assertNotNull(filter);
        assertEquals(DefaultFilterChainManager.DefaultFilter.roles.getFilterClass(), filter.getClass());

        filter = chain.get(2);
        assertNotNull(filter);
        assertEquals(DefaultFilterChainManager.DefaultFilter.perms.getFilterClass(), filter.getClass());
    }

    @Test
    public void testBeanMethods() {
        Map<String, Filter> filters = manager.getFilters();
        assertEquals(filters.size(), DefaultFilterChainManager.DefaultFilter.values().length);
        manager.setFilters(filters);
    }

    @Test
    public void testAddFilter() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);
        manager.addFilter("test", new SslFilter());
        Filter filter = manager.getFilter("test");
        assertNotNull(filter);
        assertEquals(SslFilter.class, filter.getClass());
        verify(mockFilterConfig);
    }

    @Test(expected = ConfigurationException.class)
    public void testAddFilterInitThrowsException() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        Filter mockFilter = createNiceMock(Filter.class);

        try {
            mockFilter.init(isA(FilterConfig.class));
        } catch (ServletException e) {
            fail("test setup failure.");
        }
        //noinspection ThrowableInstanceNeverThrown
        expectLastCall().andThrow(new ServletException());

        replay(mockFilterConfig);
        replay(mockFilter);

        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        this.manager.addFilter("blah", mockFilter);

        verify(mockFilterConfig);
        verify(mockFilter);
    }

    @Test(expected = IllegalStateException.class)
    public void testAddFilterNoFilterConfig() {
        manager.addFilter("test", new SslFilter());
    }

    @Test
    public void testAddToChain() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        manager.addFilter("testSsl", new SslFilter());
        manager.createChain("test", "anon");

        try {
            manager.addToChain("test", null);
        } catch (IllegalArgumentException expected) {
        }
        try {
            manager.addToChain(null, "testSsl");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testAddToChainNotPathProcessor() {
        FilterConfig mockFilterConfig = createNiceMockFilterConfig();
        replay(mockFilterConfig);
        this.manager = new DefaultFilterChainManager(mockFilterConfig);

        manager.addFilter("nonPathProcessor", new ShiroFilter());
        manager.createChain("test", "nonPathProcessor");

        try {
            manager.addToChain("test", "nonPathProcessor", "dummyConfig");
        } catch (ConfigurationException expected) {
        }
    }

    @Test
    public void testProxy() {
        FilterChain mock = createNiceMock(FilterChain.class);
        replay(mock);
        manager.createChain("test", "anon");
        this.manager.proxy(mock, "test");
        verify(mock);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testProxyNoChain() {
        FilterChain mock = createNiceMock(FilterChain.class);
        replay(mock);
        this.manager.proxy(mock, "blah");
        verify(mock);
    }
}
