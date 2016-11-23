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
package org.apache.shiro.aop

import org.apache.shiro.authz.UnauthorizedException
import org.apache.shiro.authz.aop.JavaxSecurityRolesMethodInterceptor
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.junit.Assert;
import org.junit.Test;

import static org.apache.shiro.aop.JavaxSecurityRoleStubs.*

import java.lang.reflect.Method

import static org.easymock.EasyMock.*
import static org.junit.Assert.*


/**
 * Tests for {@link JavaxSecurityRolesMethodInterceptor}.
 */
public class JavaxSecurityRolesMethodIntercepterTest {

    @Test
    public void rolesAllowedOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        expect(subject.checkRole("RoleOne"))
        assertTrue executeStubMethod(new RolesAllowedOnMethod(), subject);
    }

    @Test
    public void rolesAllowedOnClass() throws Throwable {

        Subject subject = mock(Subject)
        expect(subject.checkRole("RoleOne"))
        assertTrue executeStubMethod(new RolesAllowedOnClass(), subject);
    }


    @Test
    public void permitAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        assertTrue executeStubMethod(new PermitAllOnMethod(), subject);
    }

    @Test
    public void permitAllOnClass() throws Throwable {

        Subject subject = mock(Subject)
        assertTrue executeStubMethod(new PermitAllOnClass(), subject);
    }

    @Test(expected = UnauthorizedException.class)
    public void denyAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        executeStubMethod(new DenyAllOnMethod(), subject);
    }

    @Test(expected = UnauthorizedException.class)
    public void rolesAllowedOnClassDenyAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        executeStubMethod(new RolesAllowedOnClassDenyAllOnMethod(), subject);
    }

    @Test(expected = UnauthorizedException.class)
    public void rolesAllowedOnMethodDenyAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        executeStubMethod(new RolesAllowedOnMethodDenyAllOnMethod(), subject);
    }

    @Test
    public void rolesAllowedOnClassPermitAllOnClass() throws Throwable {

        Subject subject = mock(Subject)
        expect(subject.checkRole("RoleOne"))
        assertTrue executeStubMethod(new RolesAllowedOnClassPermitAllOnClass(), subject);
    }

    @Test
    public void rolesAllowedOnMethodPermitAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        expect(subject.checkRole("RoleOne"))
        assertTrue executeStubMethod(new RolesAllowedOnMethodPermitAllOnMethod(), subject);
    }

    @Test
    public void rolesAllowedOnClassPermitAllOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        assertTrue executeStubMethod(new RolesAllowedOnClassPermitAllOnMethod(), subject);
    }

    @Test
    public void permitAllOnClassRolesAllowedOnMethod() throws Throwable {

        Subject subject = mock(Subject)
        expect(subject.checkRole("RoleOne"))
        assertTrue executeStubMethod(new PermitAllOnClassRolesAllowedOnMethod(), subject);
    }






    static boolean executeStubMethod(final SimpleStub stub, Subject subject) {

        try {
            replay subject
            ThreadContext.bind(subject)

            JavaxSecurityRolesMethodInterceptor interceptor = new JavaxSecurityRolesMethodInterceptor();

            Object result = interceptor.invoke(new MethodInvocation() {
                @Override
                public Object proceed() throws Throwable {
                    return stub.callMe();
                }

                @Override
                public Method getMethod() {
                    try {
                        return stub.getClass().getMethod("callMe");
                    } catch (NoSuchMethodException e) {
                        Assert.fail("Failed to return method 'callMe()' on stub");
                        return null;
                    }
                }

                @Override
                public Object[] getArguments() {
                    return new Object[0];
                }

                @Override
                public Object getThis() {
                    return stub;
                }
            });

            verify subject

            return result;
        }
        finally {
            ThreadContext.unbindSubject()
        }



    }
}
