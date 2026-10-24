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
package org.apache.shiro.aop;

import org.apache.shiro.aop.fixtures.AnnotatedSubclass;
import org.apache.shiro.aop.fixtures.ComposedAnnotated;
import org.apache.shiro.aop.fixtures.GenericRepository;
import org.apache.shiro.aop.fixtures.MethodSecuredBase;
import org.apache.shiro.aop.fixtures.MethodSecuredInterface;
import org.apache.shiro.aop.fixtures.MethodSecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.MethodSecuredSubclass;
import org.apache.shiro.aop.fixtures.PlainBase;
import org.apache.shiro.aop.fixtures.RelaxedSubclass;
import org.apache.shiro.aop.fixtures.RestrictedSubclass;
import org.apache.shiro.aop.fixtures.RoleMethodBase;
import org.apache.shiro.aop.fixtures.SecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.SecuredSubclass;
import org.apache.shiro.aop.fixtures.StringRepository;
import org.apache.shiro.aop.fixtures.Unsecured;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class AnnotationHierarchyTest {

    @RequiresRoles("interface")
    interface Closer {
    }

    @RequiresRoles("base")
    static class Base {
    }

    static class Sub extends Base implements Closer {
        public void operation() {
        }
    }

    @Test
    void interfaceOfSubclassIsCloserThanSuperclass() throws Exception {
        assertThat(AnnotationHierarchy.findAnnotation(Sub.class.getMethod("operation"), Sub.class, RequiresRoles.class))
                .extracting(RequiresRoles::value).isEqualTo(new String[] {"interface"});
    }

    @Test
    void typeLevelOnInterface() throws Exception {
        Method method = SecuredInterfaceImpl.class.getMethod("adminOnly");
        assertThat(AnnotationHierarchy.findAnnotation(method, SecuredInterfaceImpl.class, RequiresRoles.class))
                .isNotNull().extracting(RequiresRoles::value).isEqualTo(new String[] {"admin"});
        Method alsoSecured = SecuredInterfaceImpl.class.getMethod("alsoSecured");
        assertThat(AnnotationHierarchy.findAnnotation(alsoSecured, SecuredInterfaceImpl.class, RequiresRoles.class))
                .as("type-level interface annotation secures every method of the implementation").isNotNull();
        assertThat(AnnotationHierarchy.isPresent(SecuredInterfaceImpl.class, RequiresRoles.class)).isTrue();
    }

    @Test
    void methodLevelOnInterface() throws Exception {
        Method read = MethodSecuredInterfaceImpl.class.getMethod("read");
        Method open = MethodSecuredInterfaceImpl.class.getMethod("open");
        assertThat(AnnotationHierarchy.findAnnotation(read, MethodSecuredInterfaceImpl.class, RequiresPermissions.class))
                .isNotNull();
        assertThat(AnnotationHierarchy.findAnnotation(open, MethodSecuredInterfaceImpl.class, RequiresPermissions.class))
                .isNull();
        assertThat(AnnotationHierarchy.isPresent(MethodSecuredInterfaceImpl.class, RequiresPermissions.class)).isTrue();
        assertThat(AnnotationHierarchy.isPresent(MethodSecuredInterfaceImpl.class, RequiresRoles.class)).isFalse();
    }

    @Test
    void interfaceMethodAsInvokedMethod() throws Exception {
        // the invoked method may be the interface declaration (JDK proxies)
        Method read = MethodSecuredInterface.class.getMethod("read");
        assertThat(AnnotationHierarchy.findAnnotation(read, MethodSecuredInterfaceImpl.class, RequiresPermissions.class))
                .isNotNull();
    }

    @Test
    void typeLevelOnSuperclass() throws Exception {
        Method method = SecuredSubclass.class.getMethod("subclassOperation");
        assertThat(AnnotationHierarchy.findAnnotation(method, SecuredSubclass.class, RequiresUser.class)).isNotNull();
        Method inherited = SecuredSubclass.class.getMethod("baseOperation");
        assertThat(AnnotationHierarchy.findAnnotation(inherited, SecuredSubclass.class, RequiresUser.class)).isNotNull();
    }

    @Test
    void methodLevelOnSuperclassOverriddenWithoutAnnotation() throws Exception {
        Method method = MethodSecuredSubclass.class.getMethod("authenticatedOperation");
        assertThat(method.getDeclaringClass()).isEqualTo(MethodSecuredSubclass.class);
        assertThat(AnnotationHierarchy.findAnnotation(method, MethodSecuredSubclass.class, RequiresAuthentication.class))
                .isNotNull();
        assertThat(AnnotationHierarchy.isPresent(MethodSecuredBase.class, RequiresAuthentication.class)).isTrue();
    }

    @Test
    void typeLevelOnSubclassProtectsInheritedMethod() throws Exception {
        Method inherited = AnnotatedSubclass.class.getMethod("inheritedOperation");
        assertThat(inherited.getDeclaringClass()).isEqualTo(PlainBase.class);
        assertThat(AnnotationHierarchy.findAnnotation(inherited, AnnotatedSubclass.class, RequiresGuest.class)).isNotNull();
        assertThat(AnnotationHierarchy.findAnnotation(inherited, PlainBase.class, RequiresGuest.class)).isNull();
    }

    @Test
    void closestDeclarationWins() throws Exception {
        Method restricted = RestrictedSubclass.class.getMethod("operation");
        assertThat(AnnotationHierarchy.findAnnotation(restricted, RestrictedSubclass.class, RequiresRoles.class))
                .as("type-level annotation on the subclass beats the method-level annotation on the superclass method")
                .extracting(RequiresRoles::value).isEqualTo(new String[] {"admin"});
        Method relaxed = RelaxedSubclass.class.getMethod("operation");
        assertThat(AnnotationHierarchy.findAnnotation(relaxed, RelaxedSubclass.class, RequiresRoles.class))
                .as("method-level annotation on the subclass beats the type-level annotation on the superclass")
                .extracting(RequiresRoles::value).isEqualTo(new String[] {"user"});
        Method base = RoleMethodBase.class.getMethod("operation");
        assertThat(AnnotationHierarchy.findAnnotation(base, RoleMethodBase.class, RequiresRoles.class))
                .extracting(RequiresRoles::value).isEqualTo(new String[] {"user"});
    }

    @Test
    void composedAnnotation() throws Exception {
        Method composed = ComposedAnnotated.class.getMethod("composed");
        Method unsecured = ComposedAnnotated.class.getMethod("unsecured");
        assertThat(AnnotationHierarchy.findAnnotation(composed, ComposedAnnotated.class, RequiresRoles.class))
                .isNotNull().extracting(RequiresRoles::value).isEqualTo(new String[] {"admin"});
        assertThat(AnnotationHierarchy.findAnnotation(unsecured, ComposedAnnotated.class, RequiresRoles.class)).isNull();
        assertThat(AnnotationHierarchy.isPresent(ComposedAnnotated.class, RequiresRoles.class)).isTrue();
    }

    @Test
    void genericOverrideWithBridgeMethod() throws Exception {
        Method bridge = Arrays.stream(StringRepository.class.getDeclaredMethods())
                .filter(Method::isBridge).findFirst().orElseThrow();
        Method real = StringRepository.class.getMethod("save", String.class);
        Method generic = GenericRepository.class.getMethod("save", Object.class);
        for (Method invoked : new Method[] {bridge, real, generic}) {
            assertThat(AnnotationHierarchy.findAnnotation(invoked, StringRepository.class, RequiresAuthentication.class))
                    .as(invoked.toString()).isNotNull();
        }
    }

    @Test
    void subclassProxyAndJdkProxyAreTransparent() throws Exception {
        SecuredInterfaceImpl anonymousSubclass = new SecuredInterfaceImpl() { };
        Method method = SecuredInterfaceImpl.class.getMethod("adminOnly");
        assertThat(AnnotationHierarchy.findAnnotation(method, anonymousSubclass.getClass(), RequiresRoles.class)).isNotNull();

        Object jdkProxy = Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {MethodSecuredInterface.class}, (proxy, m, args) -> null);
        Method read = MethodSecuredInterface.class.getMethod("read");
        assertThat(AnnotationHierarchy.findAnnotation(read, jdkProxy.getClass(), RequiresPermissions.class)).isNotNull();
    }

    @Test
    void nullTargetClassUsesDeclaringClass() throws Exception {
        Method method = SecuredInterfaceImpl.class.getMethod("adminOnly");
        assertThat(AnnotationHierarchy.findAnnotation(method, null, RequiresRoles.class)).isNotNull();
    }

    @Test
    void nothingFoundOnUnsecured() throws Exception {
        Method method = Unsecured.class.getMethod("open");
        assertThat(AnnotationHierarchy.findAnnotation(method, Unsecured.class, RequiresRoles.class)).isNull();
        assertThat(AnnotationHierarchy.isPresent(Unsecured.class, RequiresRoles.class)).isFalse();
    }

    @Test
    void resultsAreCached() throws Exception {
        Method method = SecuredInterfaceImpl.class.getMethod("adminOnly");
        RequiresRoles first = AnnotationHierarchy.findAnnotation(method, SecuredInterfaceImpl.class, RequiresRoles.class);
        RequiresRoles second = AnnotationHierarchy.findAnnotation(method, SecuredInterfaceImpl.class, RequiresRoles.class);
        assertThat(second).isSameAs(first);
    }
}
