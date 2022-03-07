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
package org.apache.shiro.spring.boot.autoconfigure

import org.apache.shiro.spring.boot.autoconfigure.application.ShiroAutoConfigurationTestApplication
import org.apache.shiro.spring.boot.autoconfigure.application.ShiroAutoConfigurationTestApplication.EventBusAwareObject
import org.apache.shiro.spring.boot.autoconfigure.application.ShiroAutoConfigurationTestApplication.SubscribedListener

import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.event.EventBus
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.subject.Subject
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner

import static org.junit.Assert.*;

/**
 * @since 1.4.0
 */
@SpringBootTest(classes = [ShiroAutoConfigurationTestApplication])
@RunWith(SpringJUnit4ClassRunner.class)
public class ShiroSpringAutoConfigurationTest {

    @Autowired
    private SecurityManager securityManager

    @Autowired
    private EventBus eventBus

    @Autowired
    private EventBusAwareObject eventBusAwareObject

    @Autowired
    private SubscribedListener subscribedListener

    @Test
    public void testMinimalConfiguration() {

        // first do a quick check of the injected objects
        assertNotNull securityManager

        assertNotNull eventBusAwareObject
        assertNotNull eventBus
        assertTrue(eventBus.registry.containsKey(subscribedListener))
        assertSame(eventBusAwareObject.getEventBus(), eventBus)
        assertSame(((DefaultSecurityManager)securityManager).getEventBus(), eventBus)

        // now lets do a couple quick permission tests to make sure everything has been initialized correctly.
        Subject joeCoder = new Subject.Builder(securityManager).buildSubject()
        joeCoder.login(new UsernamePasswordToken("joe.coder", "password"))
        joeCoder.checkPermission("read")
        assertTrue joeCoder.hasRole("user")
        assertFalse joeCoder.hasRole("admin")
        joeCoder.logout()
    }


}
