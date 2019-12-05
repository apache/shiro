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

package org.apache.shiro.authz.aop;

import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.apache.shiro.util.ThreadContext;
import org.easymock.EasyMock;
import org.junit.Test;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.lang.reflect.Method;
import java.util.Arrays;

import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

public class Jsr250AnnotationHandlerInteractionTest extends SecurityManagerTestSupport {

    @Test(expected = UnauthenticatedException.class)
    public void denyClassNoAnnotation() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleDenyAtClass(), "expectDenied");
    }

    @Test
    public void denyClassPermitMethod() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleDenyAtClass(), "expectAllowed");
    }

    @Test
    public void denyClassRolesAllowedAnnotation() throws Throwable {
        createSubject("foo");
        invokeWithInterceptor(new ExampleDenyAtClass(), "withRoles");
    }

    @Test(expected = UnauthenticatedException.class)
    public void denyClassRolesAllowedAnnotation_noRoles() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleDenyAtClass(), "withRoles");
    }

    @Test(expected = UnauthenticatedException.class)
    public void permitClassNoAnnotation() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExamplePermitAtClass(), "expectDenied");
    }

    @Test
    public void permitClassPermitMethod() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExamplePermitAtClass(), "expectAllowed");
    }

    @Test
    public void permitClassRolesAllowedAnnotation() throws Throwable {
        createSubject("foo");
        invokeWithInterceptor(new ExamplePermitAtClass(), "withRoles");
    }

    @Test(expected = UnauthenticatedException.class)
    public void permitClassRolesAllowedAnnotation_noRoles() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExamplePermitAtClass(), "withRoles");
    }

    @Test(expected = UnauthenticatedException.class)
    public void rolesAllowedNoAnnotation() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleRolesAllowedAtClass(), "expectDenied");
    }

    @Test
    public void rolesAllowedPermitMethod() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleRolesAllowedAtClass(), "expectAllowed");
    }

    @Test
    public void rolesAllowedRolesAllowedAnnotation() throws Throwable {
        createSubject("foo");
        invokeWithInterceptor(new ExampleRolesAllowedAtClass(), "withRoles");
    }

    @Test(expected = UnauthenticatedException.class)
    public void rolesAllowedRolesAllowedAnnotation_noRoles() throws Throwable {
        createSubject();
        invokeWithInterceptor(new ExampleRolesAllowedAtClass(), "withRoles");
    }

    private void invokeWithInterceptor(Object target, String methodName) throws Throwable {
        MethodInvocation mi = new StubMethodInvocation(target.getClass().getDeclaredMethod(methodName), target);
        new Jsr250MethodInterceptor().invoke(mi);
    }

    private Subject createSubject(String... roles) {
        Subject subject = createMock(Subject.class);
        Arrays.stream(roles).forEach(role -> {
            expect(subject.hasRole(role)).andReturn(true).anyTimes();
            subject.checkRole(role);
            EasyMock.expectLastCall().anyTimes();
        });
        expect(subject.hasRole(anyString())).andReturn(false).anyTimes();
        subject.checkRole(anyString());
        EasyMock.expectLastCall().andThrow(new UnauthenticatedException("Test thrown authz exception")).anyTimes();
        replay(subject);
        ThreadContext.bind(subject);
        return subject;
    }

    @DenyAll
    static class ExampleDenyAtClass {

        void expectDenied() {}

        @PermitAll
        void expectAllowed() {}

        @RolesAllowed({"blah2", "foo"})
        void withRoles() {}
    }

    @PermitAll
    static class ExamplePermitAtClass {

        @DenyAll
        void expectDenied() {}

        void expectAllowed() {}

        @RolesAllowed({"blah2", "foo"})
        void withRoles() {}
    }

    @RolesAllowed({"blah2", "foo"})
    static class ExampleRolesAllowedAtClass {

        @DenyAll
        void expectDenied() {}

        @PermitAll
        void expectAllowed() {}

        void withRoles() {}
    }

    static class StubMethodInvocation implements MethodInvocation {

        private final Method method;
        private final Object target;

        StubMethodInvocation(Method method, Object target) {
            this.method = method;
            this.target = target;
        }

        @Override
        public Object proceed() throws Throwable {
            return getMethod();
        }

        @Override
        public Method getMethod() {
            return method;
        }

        @Override
        public Object[] getArguments() {
            // returning params here instead of the actual objects
            return method.getParameters();
        }

        @Override
        public Object getThis() {
            return target;
        }
    }
}
