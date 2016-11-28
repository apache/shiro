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
package org.apache.shiro.cdi;

import org.apache.shiro.aop.MethodInterceptor;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;

import javax.annotation.Priority;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InterceptorBinding;
import javax.interceptor.InvocationContext;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

@Interceptor
@ShiroAnnotationInterceptor.ProcessShiroAnnotations
@Priority(Interceptor.Priority.LIBRARY_BEFORE + 10)
final class ShiroAnnotationInterceptor extends AnnotationsAuthorizingMethodInterceptor implements MethodInterceptor {

    @AroundInvoke
    public Object invoke(final InvocationContext invocationContext) throws Throwable {

        return invoke(new MethodInvocation() {
            @Override
            public Object proceed() throws Throwable {
                return invocationContext.proceed();
            }

            @Override
            public Method getMethod() {
                return invocationContext.getMethod();
            }

            @Override
            public Object[] getArguments() {
                return invocationContext.getParameters();
            }

            @Override
            public Object getThis() {
                return invocationContext.getTarget();
            }
        });
    }

    /**
     * A marker annotation, used to assign Shiro annotations problematically.
     */
    @InterceptorBinding
    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @interface ProcessShiroAnnotations {}

}
