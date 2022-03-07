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
package org.apache.shiro.spring.web.config

import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.realm.text.TextConfigurationRealm
import org.apache.shiro.spring.testconfig.EventBusTestConfiguration
import org.apache.shiro.spring.testconfig.RealmTestConfiguration
import org.apache.shiro.spring.web.testconfig.CacheManagerConfiguration
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

/**
 * @since 1.4.0
 */
@ContextConfiguration(classes = [EventBusTestConfiguration, RealmTestConfiguration, CacheManagerConfiguration, ShiroWebConfiguration])
@RunWith(SpringJUnit4ClassRunner.class)
public class ShiroWebConfigurationWithCacheTest {

    @Autowired
    private SecurityManager securityManager

    @Test
    public void testMinimalConfiguration() {

        // first do a quick check of the injected objects
        Assert.assertNotNull securityManager
        assertThat securityManager.realms, allOf(hasSize(1), hasItem(instanceOf(TextConfigurationRealm)))
        Assert.assertNotNull securityManager.cacheManager
    }

}
