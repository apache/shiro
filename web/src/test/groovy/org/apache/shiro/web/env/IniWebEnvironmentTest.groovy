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

import org.apache.shiro.config.CompositeBean
import org.apache.shiro.config.Ini
import org.apache.shiro.config.SimpleBean
import org.apache.shiro.web.filter.mgt.DefaultFilter
import org.junit.Test

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
        compositeBean = org.apache.shiro.config.CompositeBean
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
        compositeBean = org.apache.shiro.config.CompositeBean
        compositeBean.simpleBean = \$simpleBean
        """)

        def env = new IniWebEnvironment() {
            @Override
            protected Ini getFrameworkIni() {
                def frameworkIni = new Ini()
                frameworkIni.setSectionProperty("main", "simpleBean", "org.apache.shiro.config.SimpleBean")
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
}
