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
package org.apache.shiro.cdi.interceptor;

import org.apache.shiro.aop.MethodInterceptorSupport;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthenticatedAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.GuestAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.PermissionAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.RoleAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.UserAnnotationMethodInterceptor;

import javax.annotation.Priority;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.reflect.Method;

public abstract class ShiroInterceptorBridge implements Serializable {
    private final MethodInterceptorSupport delegate;

    protected ShiroInterceptorBridge(final MethodInterceptorSupport delegate) {
        this.delegate = delegate;
    }

    @AroundInvoke
    public Object around(final InvocationContext ic) throws Exception {
        try {
            return delegate.invoke(new MethodInvocationContext(ic));
        } catch (final Throwable throwable) {
            if (Exception.class.isInstance(throwable)) {
                throw Exception.class.cast(throwable);
            }
            if (Error.class.isInstance(throwable)) {
                throw Error.class.cast(throwable);
            }
            throw new IllegalStateException(throwable);
        }
    }

    @Interceptor
    @RequiresRoles("")
    @Priority(Interceptor.Priority.LIBRARY_BEFORE)
    public static class RequiresRolesInterceptor extends ShiroInterceptorBridge {
        public RequiresRolesInterceptor() {
            super(new RoleAnnotationMethodInterceptor());
        }
    }

    @Interceptor
    @RequiresPermissions("")
    @Priority(Interceptor.Priority.LIBRARY_BEFORE)
    public static class RequirePermissionsInterceptor extends ShiroInterceptorBridge {
        public RequirePermissionsInterceptor() {
            super(new PermissionAnnotationMethodInterceptor());
        }
    }

    @Interceptor
    @RequiresAuthentication
    @Priority(Interceptor.Priority.LIBRARY_BEFORE)
    public static class RequiresAuthenticationInterceptor extends ShiroInterceptorBridge {
        public RequiresAuthenticationInterceptor() {
            super(new AuthenticatedAnnotationMethodInterceptor());
        }
    }

    @Interceptor
    @RequiresUser
    @Priority(Interceptor.Priority.LIBRARY_BEFORE)
    public static class RequiresUserInterceptor extends ShiroInterceptorBridge {
        public RequiresUserInterceptor() {
            super(new UserAnnotationMethodInterceptor());
        }
    }

    @Interceptor
    @RequiresGuest
    @Priority(Interceptor.Priority.LIBRARY_BEFORE)
    public static class RequiresGuestInterceptor extends ShiroInterceptorBridge {
        public RequiresGuestInterceptor() {
            super(new GuestAnnotationMethodInterceptor());
        }
    }

    private static class MethodInvocationContext implements MethodInvocation {
        private final InvocationContext ic;

        private MethodInvocationContext(final InvocationContext ic) {
            this.ic = ic;
        }

        @Override
        public Object proceed() throws Throwable {
            return ic.proceed();
        }

        @Override
        public Method getMethod() {
            return ic.getMethod();
        }

        @Override
        public Object[] getArguments() {
            return ic.getParameters();
        }

        @Override
        public Object getThis() {
            return ic.getTarget();
        }
    }
}
