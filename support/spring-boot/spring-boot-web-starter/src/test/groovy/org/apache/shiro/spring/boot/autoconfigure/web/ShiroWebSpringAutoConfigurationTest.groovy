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
package org.apache.shiro.spring.boot.autoconfigure.web

import org.apache.shiro.spring.boot.autoconfigure.web.application.ShiroWebAutoConfigurationTestApplication
import org.apache.shiro.spring.boot.autoconfigure.web.application.ShiroWebAutoConfigurationTestApplication.EventBusAwareObject
import org.apache.shiro.spring.boot.autoconfigure.web.application.ShiroWebAutoConfigurationTestApplication.SubscribedListener

import org.apache.shiro.event.EventBus
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.web.filter.mgt.DefaultFilter
import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager
import org.apache.shiro.web.mgt.WebSecurityManager
import org.apache.shiro.web.servlet.AbstractShiroFilter
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests

import static org.hamcrest.Matchers.contains
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.instanceOf
import static org.junit.Assert.*
import static org.hamcrest.MatcherAssert.assertThat

/**
 * @since 1.4.0
 */
@SpringBootTest(classes = [ShiroWebAutoConfigurationTestApplication])
class ShiroWebSpringAutoConfigurationTest extends AbstractJUnit4SpringContextTests {

    @Autowired
    private SecurityManager securityManager

    @Autowired
    private EventBus eventBus

    @Autowired
    private EventBusAwareObject eventBusAwareObject

    @Autowired
    private SubscribedListener subscribedListener

    @Autowired
    private AbstractShiroFilter shiroFilter

    @Test
    void testMinimalConfiguration() {

        // first do a quick check of the injected objects
        assertNotNull securityManager
        assertThat securityManager, instanceOf(WebSecurityManager)

        assertNotNull eventBusAwareObject
        assertNotNull eventBus
        assertNotNull shiroFilter
        assertTrue(eventBus.registry.containsKey(subscribedListener))
        assertSame(eventBusAwareObject.getEventBus(), eventBus)
        assertSame(((DefaultSecurityManager)securityManager).getEventBus(), eventBus)

        // make sure global chains are configured
        assertThat shiroFilter.filterChainResolver.filterChainManager, instanceOf(DefaultFilterChainManager)
        DefaultFilterChainManager filterChainManager = shiroFilter.filterChainResolver.filterChainManager

        // default config set
        assertThat filterChainManager.globalFilterNames, equalTo([DefaultFilter.invalidRequest.name()])
        // default route configured
        assertThat filterChainManager.getChain("/**"), contains(instanceOf(DefaultFilter.invalidRequest.filterClass))
        // configured routes also contain global filters
        assertThat filterChainManager.getChain("/login.html"), contains(
                instanceOf(DefaultFilter.invalidRequest.filterClass),
                instanceOf(DefaultFilter.authc.filterClass)) // configured in ShiroWebAutoConfigurationTestApplication
    }
}
