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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.shiro.aop.AnnotationMethodInterceptor;

/**
 * Adapts a Shiro {@link org.apache.shiro.aop.MethodInterceptor MethodInterceptor} to an AOPAlliance
 * {@link org.aopalliance.intercept.MethodInterceptor}. Invocations an
 * {@link AnnotationMethodInterceptor} does not {@link AnnotationMethodInterceptor#supports support} proceed untouched.
 */
class AopAllianceMethodInterceptorAdapter implements MethodInterceptor {
    org.apache.shiro.aop.MethodInterceptor shiroInterceptor;

    AopAllianceMethodInterceptorAdapter(org.apache.shiro.aop.MethodInterceptor shiroInterceptor) {
        this.shiroInterceptor = shiroInterceptor;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        AopAllianceMethodInvocationAdapter adapted = new AopAllianceMethodInvocationAdapter(invocation);
        if (shiroInterceptor instanceof AnnotationMethodInterceptor annotationInterceptor
                && !annotationInterceptor.supports(adapted)) {
            return invocation.proceed();
        }
        return shiroInterceptor.invoke(adapted);
    }

    @Override
    public String toString() {
        return "AopAlliance Adapter for " + shiroInterceptor.toString();
    }
}
