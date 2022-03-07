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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.lang.reflect.Method;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.Test;
import static org.junit.Assert.*;


public class AnnotationResolverTest {
    @SuppressWarnings("unused")
    @RequiresRoles("root")
    private class MyFixture {
	public void operateThis() {}
        @RequiresUser()
        public void operateThat() {}
    }
    
    DefaultAnnotationResolver annotationResolver = new DefaultAnnotationResolver();

    @Test
    public void testAnnotationFoundFromClass() throws SecurityException, NoSuchMethodException {
	MyFixture myFixture = new MyFixture();
	MethodInvocation methodInvocation = createMock(MethodInvocation.class);
	Method method = MyFixture.class.getDeclaredMethod("operateThis");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(myFixture);
        replay(methodInvocation);
	assertNotNull(annotationResolver.getAnnotation(methodInvocation, RequiresRoles.class));
    }
    
    @Test
    public void testAnnotationFoundFromMethod() throws SecurityException, NoSuchMethodException {
	MethodInvocation methodInvocation = createMock(MethodInvocation.class);
	Method method = MyFixture.class.getDeclaredMethod("operateThat");
        expect(methodInvocation.getMethod()).andReturn(method);
        replay(methodInvocation);
	assertNotNull(annotationResolver.getAnnotation(methodInvocation, RequiresUser.class));
    }

    @Test
    public void testNullMethodInvocation() throws SecurityException, NoSuchMethodException {
        MethodInvocation methodInvocation = createMock(MethodInvocation.class);
        Method method = MyFixture.class.getDeclaredMethod("operateThis");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(null);
        replay(methodInvocation);
        assertNull(annotationResolver.getAnnotation(methodInvocation, RequiresUser.class));
    }
}

