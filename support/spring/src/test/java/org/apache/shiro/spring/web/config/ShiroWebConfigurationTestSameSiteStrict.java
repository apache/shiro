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

package org.apache.shiro.spring.web.config;

import org.apache.shiro.spring.testconfig.EventBusTestConfiguration;
import org.apache.shiro.spring.testconfig.RealmTestConfiguration;
import org.apache.shiro.web.servlet.Cookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {EventBusTestConfiguration.class, RealmTestConfiguration.class, ShiroWebConfiguration.class})
@TestPropertySource
public class ShiroWebConfigurationTestSameSiteStrict {

    @Autowired
    ShiroWebConfiguration shiroWebConfiguration;

    @Test
    void testStrictSameSite() {
        // given
        // org/apache/shiro/spring/web/config/ShiroWebConfigurationTestSameSiteStrict.properties

        // then
        assertEquals(Cookie.SameSiteOptions.STRICT, shiroWebConfiguration.sessionIdCookieSameSite);
        assertEquals(Cookie.SameSiteOptions.STRICT, shiroWebConfiguration.rememberMeSameSite);

        assertEquals(Cookie.SameSiteOptions.STRICT, shiroWebConfiguration.sessionCookieTemplate().getSameSite());
        assertEquals(Cookie.SameSiteOptions.STRICT, shiroWebConfiguration.rememberMeCookieTemplate().getSameSite());
    }
}
