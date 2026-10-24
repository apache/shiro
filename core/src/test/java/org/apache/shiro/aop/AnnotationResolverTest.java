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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.lang.reflect.Method;

import org.apache.shiro.aop.fixtures.MethodSecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.SecuredInterface;
import org.apache.shiro.aop.fixtures.SecuredInterfaceImpl;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.jupiter.api.Test;

public class AnnotationResolverTest {

    @SuppressWarnings("unused")
    @RequiresRoles("root")
    private static final class MyFixture {
        public void operateThis() {
        }

        @RequiresUser()
        public void operateThat() {
        }
    }

    @SuppressWarnings("unused")
    @RequiresRoles("admin")
    private static class ParentFixture {
        public void operateParent() {
        }
    }

    private static final class ChildFixture extends ParentFixture {
    }

    DefaultAnnotationResolver annotationResolver = new DefaultAnnotationResolver();

    @Test
    void testAnnotationFoundFromClass() throws SecurityException, NoSuchMethodException {
        MyFixture myFixture = new MyFixture();
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = MyFixture.class.getDeclaredMethod("operateThis");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(myFixture);
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresRoles.class)).isNotNull();
    }

    @Test
    void testAnnotationFoundFromMethod() throws SecurityException, NoSuchMethodException {
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = MyFixture.class.getDeclaredMethod("operateThat");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(new MyFixture());
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresUser.class)).isNotNull();
    }

    @Test
    void testAnnotationFoundFromSuperclass() throws SecurityException, NoSuchMethodException {
        ChildFixture childFixture = new ChildFixture();
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = ParentFixture.class.getDeclaredMethod("operateParent");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(childFixture);
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresRoles.class)).isNotNull();
    }

    @Test
    void testNullMethodInvocation() throws SecurityException, NoSuchMethodException {
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = MyFixture.class.getDeclaredMethod("operateThis");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(null);
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresUser.class)).isNull();
    }

    @Test
    void testAnnotationFoundFromInterface() throws SecurityException, NoSuchMethodException {
        SecuredInterfaceImpl target = new SecuredInterfaceImpl();
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = SecuredInterface.class.getDeclaredMethod("adminOnly");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(target);
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresRoles.class)).isNotNull();
    }

    @Test
    void testAnnotationFoundFromInterfaceMethod() throws SecurityException, NoSuchMethodException {
        MethodSecuredInterfaceImpl target = new MethodSecuredInterfaceImpl();
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = MethodSecuredInterfaceImpl.class.getDeclaredMethod("read");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(target);
        replay(methodInvocation);
        assertThat(annotationResolver.getAnnotation(methodInvocation, RequiresPermissions.class)).isNotNull();
    }

    @Test
    void testNullArguments() {
        assertThatIllegalArgumentException().isThrownBy(() -> annotationResolver.getAnnotation(null, RequiresUser.class));
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        expect(methodInvocation.getMethod()).andReturn(null);
        replay(methodInvocation);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> annotationResolver.getAnnotation(methodInvocation, RequiresUser.class));
    }
}
