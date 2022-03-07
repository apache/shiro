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
package org.apache.shiro.web.env

import org.apache.shiro.config.ogdl.CompositeBean
import org.apache.shiro.config.Ini
import org.apache.shiro.config.ogdl.SimpleBean
import org.apache.shiro.web.filter.mgt.DefaultFilter
import org.apache.shiro.web.filter.mgt.FilterChainManager
import org.hamcrest.Matchers
import org.junit.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.junit.Assert.*

/**
 * Unit tests for the {@link IniWebEnvironment} implementation.
 *
 * @since 1.2
 */
class IniWebEnvironmentTest {

    /**
     * asserts SHIRO-306
     */
    @Test
    void testObjectsAfterSecurityManagerCreation() {
        
        def ini = new Ini()
        ini.load("""
        [main]
        compositeBean = org.apache.shiro.config.ogdl.CompositeBean
        """)
        
        def env = new IniWebEnvironment(ini:  ini)
        env.init()

        assertNotNull env.objects
        //asserts that the objects size = securityManager (1) + the event bus (1) + filterChainResolverFactory (1) + num custom objects + num default filters
        def expectedSize = 4 + DefaultFilter.values().length
        assertEquals expectedSize, env.objects.size()
        assertNotNull env.objects['securityManager']
        assertNotNull env.objects['compositeBean']
    }

    /**
     * @since 1.4
     */
    @Test
    void testFrameworkConfigAdded() {

        def ini = new Ini()
        ini.load("""
        [main]
        compositeBean = org.apache.shiro.config.ogdl.CompositeBean
        compositeBean.simpleBean = \$simpleBean
        """)

        def env = new IniWebEnvironment() {
            @Override
            protected Ini getFrameworkIni() {
                def frameworkIni = new Ini()
                frameworkIni.setSectionProperty("main", "simpleBean", "org.apache.shiro.config.ogdl.SimpleBean")
                return frameworkIni;
            }
        }
        env.ini = ini
        env.init()

        assertNotNull env.objects
        //asserts that the objects size = securityManager (1) + the event bus (1) + filterChainResolverFactory (1) + num custom objects + num default filters
        def expectedSize = 5 + DefaultFilter.values().length
        assertEquals expectedSize, env.objects.size()
        assertNotNull env.objects['securityManager']

        def compositeBean = (CompositeBean) env.objects['compositeBean']
        def simpleBean = (SimpleBean) env.objects['simpleBean']

        assertNotNull compositeBean
        assertNotNull simpleBean

        assertSame(compositeBean.simpleBean, simpleBean)
    }

    @Test
    void testDisableGlobalFilters() {
        Ini ini = new Ini()
        ini.load("""
        [main]
        filterChainResolver.globalFilters = null

        [urls]
        /index.html = anon
        """)

        def env = new IniWebEnvironment(ini:  ini)
        env.init()
        assertThat env.getFilterChainResolver().filterChainManager.globalFilterNames, Matchers.empty()
    }

    @Test
    void testDefaultGlobalFilters() {
        Ini ini = new Ini()
        ini.load("""
        [main]

        [urls]
        /index.html = anon
        """)

        def env = new IniWebEnvironment(ini:  ini)
        env.init()
        def resolver =  env.getFilterChainResolver()
        FilterChainManager manager = resolver.filterChainManager
        assertThat manager.globalFilterNames, Matchers.contains(DefaultFilter.invalidRequest.name())

        assertThat manager.getChain("/index.html"), Matchers.contains(
                Matchers.instanceOf(DefaultFilter.invalidRequest.filterClass),
                Matchers.instanceOf(DefaultFilter.anon.filterClass))
    }

    @Test
    void testCustomGlobalFilters() {
        Ini ini = new Ini()
        ini.load("""
        [main]
        stub = org.apache.shiro.web.env.FilterStub
        filterChainResolver.globalFilters = port,invalidRequest,stub

        [urls]
        /index.html = authc
        """)

        def env = new IniWebEnvironment(ini:  ini)
        env.init()
        def resolver =  env.getFilterChainResolver()
        FilterChainManager manager = resolver.filterChainManager
        assertThat manager.globalFilterNames, Matchers.contains(
                DefaultFilter.port.name(),
                DefaultFilter.invalidRequest.name(),
                "stub"
        )

        assertThat manager.getChain("/index.html"), Matchers.contains(
                Matchers.instanceOf(DefaultFilter.port.filterClass),
                Matchers.instanceOf(DefaultFilter.invalidRequest.filterClass),
                Matchers.instanceOf(FilterStub),
                Matchers.instanceOf(DefaultFilter.authc.filterClass))
    }
}
