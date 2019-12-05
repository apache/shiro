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

import org.apache.shiro.aop.MethodInterceptorSupport;
import org.apache.shiro.aop.MethodInvocation;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class Jsr250MethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    private final Map<Class<? extends Annotation>, AuthorizingAnnotationHandler> handlerMap = new HashMap<>();

    public Jsr250MethodInterceptor() {

        // NOTE: in order for this package to retain backwards compatibility, it MUST extend AuthorizingAnnotationMethodInterceptor
        // which only supports a single Handler.  JSR 250 annotations require knowledge of other annotations (PermitAll on a method
        // overrides DenyAll at the class level).  Using the most restrictive handler here as a place holder.
        super(new DenyAllAnnotationHandler());

        handlerMap.put(DenyAll.class, new DenyAllAnnotationHandler());
        handlerMap.put(PermitAll.class, new PermitAllAnnotationHandler());
        handlerMap.put(RolesAllowed.class, new RolesAllowedAnnotationHandler());
    }

    @Override
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        assertAuthorized(methodInvocation);
        return methodInvocation.proceed();
    }

    @Override
    public void assertAuthorized(MethodInvocation methodInvocation) {
        if (methodInvocation == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }

        Annotation annotation = getAnnotation(methodInvocation);
        if (annotation != null) {
            AuthorizingAnnotationHandler handler = handlerMap.get(annotation.annotationType());
            handler.assertAuthorized(annotation);
        }
    }

    @Override
    public Annotation getAnnotation(MethodInvocation methodInvocation) {

        Method method = methodInvocation.getMethod();
        if (method == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);

        }

        // look for DenyAll, PermitAll, and AllowedRoles in that order
        Annotation annotation = method.getAnnotation(DenyAll.class);

        if (annotation == null) {
            annotation = method.getAnnotation(PermitAll.class);
        }

        if (annotation == null) {
            annotation = method.getAnnotation(RolesAllowed.class);
        }

        // if still null check at the class level
        Object miThis = methodInvocation.getThis();
        if (annotation == null && miThis != null) {

            annotation = miThis.getClass().getAnnotation(DenyAll.class);

            if (annotation == null) {
                annotation = miThis.getClass().getAnnotation(PermitAll.class);
            }

            if (annotation == null) {
                annotation = miThis.getClass().getAnnotation(RolesAllowed.class);
            }
        }

        return annotation;
    }
}
