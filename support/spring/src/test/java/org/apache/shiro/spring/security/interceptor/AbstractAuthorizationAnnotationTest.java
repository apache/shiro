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
package org.apache.shiro.spring.security.interceptor;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadState;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Common method tests across implementations.  In actuality, the methods don't change across
 * subclasses - only the mechanism that enables AOP pointcuts and applies advice.  Those differences
 * are in spring configuration only.
 *
 * @since 1.1
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public abstract class AbstractAuthorizationAnnotationTest {

    @Autowired
    protected TestService testService;
    @Autowired
    private org.apache.shiro.mgt.SecurityManager securityManager;
    @Autowired
    private Realm realm;

    private ThreadState threadState;

    protected void bind(Subject subject) {
        clearSubject();
        this.threadState = new SubjectThreadState(subject);
        this.threadState.bind();
    }

    @After
    public void clearSubject() {
        if (threadState != null) {
            threadState.clear();
        }
    }

    protected void bindGuest() {
        bind(new Subject.Builder(securityManager).buildSubject());
    }

    protected void bindUser() {
        PrincipalCollection principals = new SimplePrincipalCollection("test", realm.getName());
        bind(new Subject.Builder(securityManager).principals(principals).buildSubject());
    }

    protected void bindAuthenticatedUser() {
        PrincipalCollection principals = new SimplePrincipalCollection("test", realm.getName());
        bind(new Subject.Builder(securityManager).
                principals(principals).authenticated(true).buildSubject());
    }

    // GUEST OPERATIONS:

    @Test
    public void testGuestImplementation() {
        bindGuest();
        testService.guestImplementation();
    }

    @Test(expected = UnauthenticatedException.class)
    public void testGuestImplementationFailure() {
        bindUser();
        testService.guestImplementation();
    }

    @Test
    public void testGuestInterface() {
        bindGuest();
        testService.guestInterface();
    }
    //testGuestInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass


    // USER OPERATIONS

    @Test
    public void testUserImplementation() {
        bindUser();
        testService.userImplementation();
    }

    @Test(expected = UnauthenticatedException.class)
    public void testUserImplementationFailure() {
        bindGuest();
        testService.userImplementation();
    }

    @Test
    public void testUserInterface() {
        bindUser();
        testService.userInterface();
    }
    //testUserInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass


    // AUTHENTICATED USER OPERATIONS

    @Test
    public void testAuthenticatedImplementation() {
        bindAuthenticatedUser();
        testService.authenticatedImplementation();
    }

    @Test(expected = UnauthenticatedException.class)
    public void testAuthenticatedImplementationFailure() {
        bindUser();
        testService.authenticatedImplementation();
    }

    @Test
    public void testAuthenticatedInterface() {
        bindAuthenticatedUser();
        testService.authenticatedInterface();
    }
    //testAuthenticatedInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass
}
