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
import org.apache.shiro.aop.MethodInterceptor;
import org.easymock.IAnswer;
import org.junit.jupiter.api.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.getCurrentArguments;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.assertSame;


public class AopAllianceMethodInterceptorAdapterTest {
    @Test
    void testInvoke() throws Throwable {
        MethodInvocation allianceInvocation = createMock(MethodInvocation.class);
        MethodInterceptor mockShiroInterceptor = createMock(MethodInterceptor.class);
        expect(mockShiroInterceptor.invoke(anyObject(AopAllianceMethodInvocationAdapter.class))).andAnswer(new IAnswer<Object>() {
            public Object answer() throws Throwable {
                return getCurrentArguments()[0];
            }
        });
        final Object expectedValue = new Object();
        expect(allianceInvocation.proceed()).andReturn(expectedValue);

        replay(mockShiroInterceptor, allianceInvocation);

        AopAllianceMethodInterceptorAdapter underTest = new AopAllianceMethodInterceptorAdapter(mockShiroInterceptor);
        Object invocation = underTest.invoke(allianceInvocation);
        Object value = ((AopAllianceMethodInvocationAdapter) invocation).proceed();

        assertSame(expectedValue, value, "Adapter invocation returned a different value.");

        verify(mockShiroInterceptor, allianceInvocation);
    }
}
