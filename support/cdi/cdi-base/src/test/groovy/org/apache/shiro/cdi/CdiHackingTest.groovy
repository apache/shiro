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
package org.apache.shiro.cdi

import org.apache.deltaspike.testcontrol.api.junit.CdiTestRunner
import org.apache.shiro.authc.Authenticator
import org.apache.shiro.authz.Authorizer
import org.apache.shiro.authz.permission.PermissionResolver
import org.apache.shiro.cache.CacheManager
import org.apache.shiro.event.EventBus
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.mgt.RememberMeManager
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.mgt.SubjectDAO
import org.apache.shiro.mgt.SubjectFactory
import org.apache.shiro.realm.Realm
import org.apache.shiro.session.mgt.DefaultSessionKey
import org.apache.shiro.session.mgt.SessionManager
import org.apache.shiro.subject.Subject
import org.junit.Test
import org.junit.runner.RunWith

import javax.enterprise.context.ApplicationScoped
import javax.enterprise.inject.Default
import javax.enterprise.inject.Instance
import javax.inject.Inject

import static org.hamcrest.Matchers.*

import static org.junit.Assert.*

/**
 * Hacking around with CDI and Shiro.
 */
@RunWith(CdiTestRunner.class)
@Default
@ApplicationScoped
public class CdiHackingTest {

//    @Inject
//    private SecurityManager securityManager;
//
//    @Inject
//    private CdiEnvironment cdiEnvironment;
//
//    @Inject
//    private EventBus eventBus;
//
//    @Inject
//    private Instance<Realm> realms;
//
//    @Inject
//    private SessionManager sessionManager
//
//    @Inject
//    private Instance<CacheManager> cacheManager;
//
//    @Inject
//    private SubjectDAO subjectDAO;
//
//    @Inject
//    private SubjectFactory subjectFactory;
//
//    @Inject
//    private Instance<RememberMeManager> rememberMeManager;
//
//    @Inject
//    private Instance<PermissionResolver> permissionResolver;
//
//    @Inject
//    private Subject subject;

    @Test
    public void doSomeStuff() {

//        assertNotNull(eventBus)
//        assertNotNull(subjectFactory)
//        assertNotNull(subjectDAO)
//        assertNotNull(sessionManager)
//
//        assertTrue(rememberMeManager.isUnsatisfied())
//        assertTrue(cacheManager.isUnsatisfied())
//
//        assertNotNull(permissionResolver.get())
//
//        assertSame cdiEnvironment.securityManager, securityManager
//        assertThat securityManager, instanceOf(DefaultSecurityManager)
//
//        assertEquals sessionManager, securityManager.getSessionManager()
////        sessionManager.getSession(new DefaultSessionKey("foo"))
//
//        assertFalse subject.isAuthenticated()


    }
}
