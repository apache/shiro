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
package org.ki.spring.security.interceptor;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.ki.authz.aop.AnnotationsAuthorizingMethodInterceptor;

import java.lang.reflect.Method;

/**
 * Allows JSecurity Annotations to work in any <a href="http://aopalliance.sourceforge.net/">AOP Alliance</a>
 * specific implementation environment (for example, Spring).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class AopAllianceAnnotationsAuthorizingMethodInterceptor
        extends AnnotationsAuthorizingMethodInterceptor implements MethodInterceptor {

    /**
     * Creates a {@link MethodInvocation MethodInvocation} that wraps an
     * {@link org.aopalliance.intercept.MethodInvocation org.aopalliance.intercept.MethodInvocation} instance,
     * enabling JSecurity Annotations in <a href="http://aopalliance.sourceforge.net/">AOP Alliance</a> environments
     * (Spring, etc).
     *
     * @param implSpecificMethodInvocation AOP Alliance {@link org.aopalliance.intercept.MethodInvocation MethodInvocation}
     * @return a JSecurity {@link MethodInvocation MethodInvocation} instance that wraps the AOP Alliance instance.
     */
    protected org.ki.aop.MethodInvocation createMethodInvocation(Object implSpecificMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) implSpecificMethodInvocation;

        return new org.ki.aop.MethodInvocation() {
            public Method getMethod() {
                return mi.getMethod();
            }

            public Object[] getArguments() {
                return mi.getArguments();
            }

            public String toString() {
                return "Method invocation [" + mi.getMethod() + "]";
            }

            public Object proceed() throws Throwable {
                return mi.proceed();
            }
        };
    }

    /**
     * Simply casts the method argument to an
     * {@link org.aopalliance.intercept.MethodInvocation org.aopalliance.intercept.MethodInvocation} and then
     * calls <code>methodInvocation.{@link org.aopalliance.intercept.MethodInvocation#proceed proceed}()</code>
     * @param aopAllianceMethodInvocation the {@link org.aopalliance.intercept.MethodInvocation org.aopalliance.intercept.MethodInvocation}
     * @return the {@link org.aopalliance.intercept.MethodInvocation#proceed() org.aopalliance.intercept.MethodInvocation.proceed()} method call result.
     * @throws Throwable if the underlying AOP Alliance <code>proceed()</code> call throws a <code>Throwable</code>.
     */
    protected Object continueInvocation(Object aopAllianceMethodInvocation) throws Throwable {
        MethodInvocation mi = (MethodInvocation) aopAllianceMethodInvocation;
        return mi.proceed();
    }

    /**
     * Creates a JSecurity {@link MethodInvocation MethodInvocation} instance and then immediately calls
     * {@link org.ki.authz.aop.AuthorizingMethodInterceptor#invoke super.invoke}.
     *
     * @param methodInvocation the AOP Alliance-specific <code>methodInvocation</code> instance.
     * @return the return value from invoking the method invocation.
     * @throws Throwable if the underlying AOP Alliance method invocation throws a <code>Throwable</code>.
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        org.ki.aop.MethodInvocation mi = createMethodInvocation(methodInvocation);
        return super.invoke(mi);
    }
}
