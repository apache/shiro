/**
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
package org.apache.shiro.cdi.interceptor;

import java.lang.reflect.Method;

import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;
import org.apache.shiro.cdi.ShiroSecured;

/**
 * An interceptor for declarative security checks using the annotations from the 
 * {@code org.apache.shiro.authz.annotation} package.
 *
 */
@Interceptor
@ShiroSecured
public class ShiroInterceptor extends AnnotationsAuthorizingMethodInterceptor {
    @AroundInvoke
    public Object around(final InvocationContext ic) throws Exception {
        assertAuthorized(new InvocationContextToMethodInvocationConverter(ic));
        return ic.proceed();
    }

    private static class InvocationContextToMethodInvocationConverter implements MethodInvocation {
        private final InvocationContext context;

        public InvocationContextToMethodInvocationConverter(InvocationContext ctx) {
            context = ctx;
        }

        // CHECKSTYLE:SKIP - interceptor API
        public Object proceed() throws Exception  {
            return context.proceed();
        }

        public Method getMethod() {
            return context.getMethod();
        }

        public Object[] getArguments() {
            return context.getParameters();
        }

        public Object getThis() {
            return context.getTarget();
        }
    }
}
