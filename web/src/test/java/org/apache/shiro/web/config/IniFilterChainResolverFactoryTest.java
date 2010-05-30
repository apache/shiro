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
package org.apache.shiro.web.config;

import org.apache.shiro.config.Ini;
import org.apache.shiro.web.WebTest;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import java.util.Map;

import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Tests for the {@link IniFilterChainResolverFactory}.
 *
 * @since 1.0
 */
public class IniFilterChainResolverFactoryTest extends WebTest {

    private IniFilterChainResolverFactory factory;

    @Before
    public void setUp() {
        this.factory = new IniFilterChainResolverFactory();
    }

    @Test
    public void testNewInstance() {
        assertNull(factory.getFilterConfig());
        factory.setFilterConfig(null);
        assertNull(factory.getFilterConfig());
    }

    @Test
    public void testGetInstanceNoIni() {
        FilterChainResolver resolver = factory.getInstance();
        assertNotNull(resolver);
    }

    @Test
    public void testNewInstanceWithIni() {
        Ini ini = new Ini();
        String config =
                "[urls]\n" +
                        "/index.html = anon";
        ini.load(config);
        factory = new IniFilterChainResolverFactory(ini);
        FilterChainResolver resolver = factory.getInstance();
        assertNotNull(resolver);
    }

    @Test
    public void testGetFiltersWithNullOrEmptySection() {
        Map<String, Filter> filters = factory.getFilters(null, null);
        assertNull(filters);
    }

    @Test
    public void testCreateChainsWithNullUrlsSection() {
        //should do nothing (return immediately, no exceptions):
        factory.createChains(null, null);
    }

    @Test
    public void testNewInstanceWithNonFilter() {
        Ini ini = new Ini();
        String config =
                "[filters]\n" +
                        "test = org.apache.shiro.web.servlet.SimpleCookie\n" + //any non-Filter will do
                        "[urls]\n" +
                        "/index.html = anon";
        ini.load(config);
        factory = new IniFilterChainResolverFactory(ini);
        factory.getInstance();
    }

    @Test
    public void testNewInstanceWithFilterConfig() {
        Ini ini = new Ini();
        String text =
                "[urls]\n" +
                        "/index.html = anon";
        ini.load(text);
        factory = new IniFilterChainResolverFactory(ini);
        FilterConfig config = createNiceMockFilterConfig();
        factory.setFilterConfig(config);
        replay(config);
        FilterChainResolver resolver = factory.getInstance();
        assertNotNull(resolver);
        verify(config);
    }
}
