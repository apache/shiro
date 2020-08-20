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
import org.apache.shiro.mgt.SessionStorageEvaluator
import org.apache.shiro.realm.text.TextConfigurationRealm
import org.apache.shiro.spring.testconfig.EventBusTestConfiguration
import org.apache.shiro.spring.testconfig.RealmTestConfiguration
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator
import org.apache.shiro.web.mgt.WebSecurityManager
import org.apache.shiro.web.servlet.Cookie
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.function.Executable
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.expression.Expression
import org.springframework.expression.ExpressionParser
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.junit.Assert.*

/**
 * @since 1.4.0
 */
@ContextConfiguration(classes = [EventBusTestConfiguration, RealmTestConfiguration, ShiroWebConfiguration])
@RunWith(SpringJUnit4ClassRunner.class)
public class ShiroWebConfigurationTest {

    @Autowired
    private SecurityManager securityManager

    @Autowired
    @Qualifier("rememberMeCookieTemplate")
    private Cookie rememberMeCookie;

    @Autowired
    @Qualifier("sessionCookieTemplate")
    private Cookie sessionCookieTemplate;

    @Autowired
    private SessionStorageEvaluator sessionStorageEvaluator;

    @Test
    public void testMinimalConfiguration() {

        // first do a quick check of the injected objects
        assertNotNull securityManager
        assertNotNull sessionStorageEvaluator
        assertThat sessionStorageEvaluator, instanceOf(DefaultWebSessionStorageEvaluator)
        assertThat securityManager, instanceOf(WebSecurityManager)
        assertThat securityManager.realms, allOf(hasSize(1), hasItem(instanceOf(TextConfigurationRealm)))
        assertNull securityManager.cacheManager


//        // now lets do a couple quick permission tests to make sure everything has been initialized correctly.
//        Subject joeCoder = new Subject.Builder(securityManager).buildSubject()
//        joeCoder.login(new UsernamePasswordToken("joe.coder", "password"))
//        joeCoder.checkPermission("read")
//        assertTrue joeCoder.hasRole("user")
//        assertFalse joeCoder.hasRole("admin")
//        joeCoder.logout()
    }

    @Test
    public void fakeCookie() {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression("T(org.apache.shiro.web.mgt.CookieRememberMeManager).DEFAULT_REMEMBER_ME_COOKIE_NAME");
//        Expression exp = parser.parseExpression("@environment['shiro.rememberMeManager.cookie.name'] ?: T(org.apache.shiro.web.mgt.CookieRememberMeManager).DEFAULT_REMEMBER_ME_COOKIE_NAME");

        String message = (String) exp.getValue();

        println(message);
    }

    @Test
    void testSameSiteOptionExpression() {
        ExpressionParser parser = new SpelExpressionParser();
        Executable expressionParser = () -> parser.parseExpression("T(org.apache.shiro.web.servlet.Cookie.SameSiteOptions).LAX")
        Assertions.assertDoesNotThrow expressionParser;
    }

    @Test
    public void rememberMeCookie() {
        assertEquals "rememberMe", rememberMeCookie.name
    }

    @Test
    public void sessionCookie() {
        assertSame "JSESSIONID", sessionCookieTemplate.name

    }

    @Test
    void sameSiteOption() {
        assertSame Cookie.SameSiteOptions.LAX, rememberMeCookie.sameSite
        assertSame Cookie.SameSiteOptions.LAX, sessionCookieTemplate.sameSite
    }
}
