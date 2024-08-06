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
import org.apache.shiro.subject.ImmutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Common method tests across implementations.  In actuality, the methods don't change across
 * subclasses - only the mechanism that enables AOP pointcuts and applies advice.  Those differences
 * are in spring configuration only.
 *
 * @since 1.1
 */
@ExtendWith(SpringExtension.class)
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

    @AfterEach
    public void clearSubject() {
        if (threadState != null) {
            threadState.clear();
        }
    }

    protected void bindGuest() {
        bind(new Subject.Builder(securityManager).buildSubject());
    }

    protected void bindUser() {
        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal("test", realm.getName());
        bind(new Subject.Builder(securityManager).principals(principals).buildSubject());
    }

    protected void bindAuthenticatedUser() {
        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal("test", realm.getName());
        bind(new Subject.Builder(securityManager).
                principals(principals).authenticated(true).buildSubject());
    }

    // GUEST OPERATIONS:

    @Test
    void testGuestImplementation() {
        bindGuest();
        testService.guestImplementation();
    }

    @Test
    void testGuestImplementationFailure() {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            bindUser();
            testService.guestImplementation();
        });
    }

    @Test
    void testGuestInterface() {
        bindGuest();
        testService.guestInterface();
    }

    //testGuestInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass


    // USER OPERATIONS

    @Test
    void testUserImplementation() {
        bindUser();
        testService.userImplementation();
    }

    @Test
    void testUserImplementationFailure() {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            bindGuest();
            testService.userImplementation();
        });
    }

    @Test
    void testUserInterface() {
        bindUser();
        testService.userInterface();
    }

    //testUserInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass


    // AUTHENTICATED USER OPERATIONS

    @Test
    void testAuthenticatedImplementation() {
        bindAuthenticatedUser();
        testService.authenticatedImplementation();
    }

    @Test
    void testAuthenticatedImplementationFailure() {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            bindUser();
            testService.authenticatedImplementation();
        });
    }

    @Test
    void testAuthenticatedInterface() {
        bindAuthenticatedUser();
        testService.authenticatedInterface();
    }
    //testAuthenticatedInterfaceFailure() cannot be in this class - the SchemaAuthorizationAnnotationTest
    //subclass does not support annotations on interfaces (Spring AspectJ pointcut expressions
    //do not support annotations on interface methods).  It is instead in the
    //DapcAuthorizationAnnotationTest subclass
}
