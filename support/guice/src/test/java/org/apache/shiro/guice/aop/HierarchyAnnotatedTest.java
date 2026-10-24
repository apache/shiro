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
package org.apache.shiro.guice.aop;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.apache.shiro.aop.fixtures.AnnotatedSubclass;
import org.apache.shiro.aop.fixtures.ComposedAnnotated;
import org.apache.shiro.aop.fixtures.MethodSecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.MethodSecuredSubclass;
import org.apache.shiro.aop.fixtures.SecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.SecuredSubclass;
import org.apache.shiro.aop.fixtures.StringRepository;
import org.apache.shiro.aop.fixtures.Unsecured;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Annotations on interfaces, superclasses, subclasses and composed annotations are enforced by Guice
 * exactly as by the other integrations.
 */
class HierarchyAnnotatedTest {
    private final Injector injector = Guice.createInjector(new ShiroAopModule());

    @Test
    void interfaceTypeLevel() {
        SecuredInterfaceImpl service = injector.getInstance(SecuredInterfaceImpl.class);
        as("alice", () -> {
            assertThatThrownBy(service::adminOnly).isInstanceOf(AuthorizationException.class);
            assertThatThrownBy(service::alsoSecured).isInstanceOf(AuthorizationException.class);
        });
        as("root", () -> assertThat(service.adminOnly()).isEqualTo("admin"));
    }

    @Test
    void interfaceMethodLevel() {
        MethodSecuredInterfaceImpl service = injector.getInstance(MethodSecuredInterfaceImpl.class);
        as("alice", () -> {
            assertThatThrownBy(service::read).isInstanceOf(AuthorizationException.class);
            assertThat(service.open()).isEqualTo("open");
        });
    }

    @Test
    void genericInterfaceMethodWithBridge() {
        StringRepository repository = injector.getInstance(StringRepository.class);
        asGuest(() -> assertThatThrownBy(() -> repository.save("x")).isInstanceOf(UnauthenticatedException.class));
        as("alice", () -> assertThat(repository.save("x")).isEqualTo("x"));
    }

    @Test
    void superclassTypeLevelAndOverriddenMethod() {
        SecuredSubclass subclass = injector.getInstance(SecuredSubclass.class);
        asGuest(() -> {
            assertThatThrownBy(subclass::subclassOperation).isInstanceOf(UnauthenticatedException.class);
            assertThatThrownBy(subclass::baseOperation).isInstanceOf(UnauthenticatedException.class);
        });
        MethodSecuredSubclass overriding = injector.getInstance(MethodSecuredSubclass.class);
        asGuest(() -> assertThatThrownBy(overriding::authenticatedOperation).isInstanceOf(UnauthenticatedException.class));
        as("alice", () -> assertThat(overriding.authenticatedOperation()).isEqualTo("sub"));
    }

    @Test
    void subclassTypeLevelProtectsInheritedMethod() {
        AnnotatedSubclass service = injector.getInstance(AnnotatedSubclass.class);
        as("alice", () -> assertThatThrownBy(service::inheritedOperation).isInstanceOf(AuthorizationException.class));
        asGuest(() -> assertThat(service.inheritedOperation()).isEqualTo("plain"));
    }

    @Test
    void composedAnnotation() {
        ComposedAnnotated service = injector.getInstance(ComposedAnnotated.class);
        as("alice", () -> {
            assertThatThrownBy(service::composed).isInstanceOf(AuthorizationException.class);
            assertThat(service.unsecured()).isEqualTo("open");
        });
    }

    @Test
    void unsecuredClassIsNotEnhanced() {
        Unsecured service = injector.getInstance(Unsecured.class);
        assertThat(service.getClass()).isEqualTo(Unsecured.class);
        assertThat(injector.getInstance(SecuredInterfaceImpl.class).getClass()).isNotEqualTo(SecuredInterfaceImpl.class);
    }

    private static DefaultSecurityManager securityManager() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("alice", "secret", "user");
        realm.addAccount("root", "secret", "admin", "user");
        return new DefaultSecurityManager(realm);
    }

    private static void asGuest(Runnable action) {
        new Subject.Builder(securityManager()).buildSubject().execute(action);
    }

    private static void as(String user, Runnable action) {
        Subject subject = new Subject.Builder(securityManager()).buildSubject();
        subject.login(new UsernamePasswordToken(user, "secret"));
        try {
            subject.execute(action);
        } finally {
            subject.logout();
        }
    }
}
