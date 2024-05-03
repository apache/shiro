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

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

/**
 * Created by IntelliJ IDEA.
 * User: jbunting
 * Date: 6/18/11
 * Time: 5:02 PM
 * To change this template use File | Settings | File Templates.
 */
public class AopAllianceMethodInvocationAdapterTest {
    @Test
    public void testGetMethod() throws Exception {
        MethodInvocation mock = createMock(MethodInvocation.class);
        Method method = AopAllianceMethodInvocationAdapterTest.class.getMethod("testGetMethod");
        expect(mock.getMethod()).andReturn(method);
        AopAllianceMethodInvocationAdapter underTest = new AopAllianceMethodInvocationAdapter(mock);

        replay(mock);

        assertThat(underTest.getMethod()).isSameAs(method);

        verify(mock);
    }

    @Test
    void testGetArguments() throws Exception {
        MethodInvocation mock = createMock(MethodInvocation.class);
        Object[] args = new Object[0];
        expect(mock.getArguments()).andReturn(args);
        AopAllianceMethodInvocationAdapter underTest = new AopAllianceMethodInvocationAdapter(mock);

        replay(mock);

        assertThat(underTest.getArguments()).isSameAs(args);

        verify(mock);
    }

    @Test
    void testProceed() throws Throwable {
        MethodInvocation mock = createMock(MethodInvocation.class);
        Object value = new Object();
        expect(mock.proceed()).andReturn(value);
        AopAllianceMethodInvocationAdapter underTest = new AopAllianceMethodInvocationAdapter(mock);

        replay(mock);

        assertThat(underTest.proceed()).isSameAs(value);

        verify(mock);
    }

    @Test
    void testGetThis() throws Exception {
        MethodInvocation mock = createMock(MethodInvocation.class);
        Object value = new Object();
        expect(mock.getThis()).andReturn(value);
        AopAllianceMethodInvocationAdapter underTest = new AopAllianceMethodInvocationAdapter(mock);

        replay(mock);

        assertThat(underTest.getThis()).isSameAs(value);

        verify(mock);
    }
}
