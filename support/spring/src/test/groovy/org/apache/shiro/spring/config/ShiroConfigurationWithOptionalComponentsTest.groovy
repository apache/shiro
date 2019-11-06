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
package org.apache.shiro.spring.config

import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.authz.ModularRealmAuthorizer
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.realm.text.TextConfigurationRealm
import org.apache.shiro.spring.testconfig.OptionalComponentsTestConfiguration
import org.apache.shiro.spring.testconfig.RealmTestConfiguration
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor
import org.apache.shiro.subject.Subject
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests

import static org.junit.Assert.*
import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.*

/**
 * @since 1.4.0
 */
@ContextConfiguration(classes = [RealmTestConfiguration, OptionalComponentsTestConfiguration, ShiroConfiguration, ShiroAnnotationProcessorConfiguration])
public class ShiroConfigurationWithOptionalComponentsTest extends AbstractJUnit4SpringContextTests {

    @Autowired
    private SecurityManager securityManager

    @Autowired
    private AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor

    @Test
    public void testMinimalConfiguration() {

        // first do a quick check of the injected objects
        assertNotNull authorizationAttributeSourceAdvisor
        assertNotNull securityManager
        assertSame securityManager, authorizationAttributeSourceAdvisor.securityManager
        assertThat securityManager.realms, allOf(hasSize(1), hasItem(instanceOf(TextConfigurationRealm)))
        assertNotNull securityManager.cacheManager

        def defaultSecurityManager = (DefaultSecurityManager) securityManager
        def authorizor = (ModularRealmAuthorizer) defaultSecurityManager.getAuthorizer();
        assertNotNull authorizor.rolePermissionResolver
        assertNotNull authorizor.permissionResolver

        // now lets do a couple quick permission tests to make sure everything has been initialized correctly.
        Subject joeCoder = new Subject.Builder(securityManager).buildSubject()
        joeCoder.login(new UsernamePasswordToken("joe.coder", "password"))
        joeCoder.checkPermission("read")
        assertTrue joeCoder.hasRole("user")
        assertFalse joeCoder.hasRole("admin")
        joeCoder.logout()
    }

}
