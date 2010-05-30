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

import java.util.ArrayList;
import java.util.Collection;

import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.AuthorizationException;

/**
 * An <tt>AnnotationsAuthorizingMethodInterceptor</tt> is a MethodInterceptor that asserts a given method is authorized
 * to execute based on one or more configured <tt>AuthorizingAnnotationMethodInterceptor</tt>s.
 *
 * <p>This allows multiple annotations on a method to be processed before the method
 * executes, and if any of the <tt>AuthorizingAnnotationMethodInterceptor</tt>s indicate that the method should not be
 * executed, an <tt>AuthorizationException</tt> will be thrown, otherwise the method will be invoked as expected.
 *
 * <p>It is essentially a convenience mechanism to allow multiple annotations to be processed in a single method
 * interceptor.
 *
 * @since 0.2
 */
public abstract class AnnotationsAuthorizingMethodInterceptor extends AuthorizingMethodInterceptor {

    /**
     * The method interceptors to execute for the annotated method.
     */
    protected Collection<AuthorizingAnnotationMethodInterceptor> methodInterceptors;

    /**
     * Default no-argument constructor that defaults the 
     * {@link #methodInterceptors methodInterceptors} attribute to contain two interceptors by default - the
     * {@link RoleAnnotationMethodInterceptor RoleAnnotationMethodInterceptor} and the
     * {@link PermissionAnnotationMethodInterceptor PermissionAnnotationMethodInterceptor} to
     * support role and permission annotations.
     */
    public AnnotationsAuthorizingMethodInterceptor() {
        methodInterceptors = new ArrayList<AuthorizingAnnotationMethodInterceptor>(5);
        methodInterceptors.add(new RoleAnnotationMethodInterceptor());
        methodInterceptors.add(new PermissionAnnotationMethodInterceptor());
        methodInterceptors.add(new AuthenticatedAnnotationMethodInterceptor());
        methodInterceptors.add(new UserAnnotationMethodInterceptor());
        methodInterceptors.add(new GuestAnnotationMethodInterceptor());
    }

    /**
     * Returns the method interceptors to execute for the annotated method.
     * <p/>
     * Unless overridden by the {@link #setMethodInterceptors(java.util.Collection)} method, the default collection
     * contains a
     * {@link RoleAnnotationMethodInterceptor RoleAnnotationMethodInterceptor} and a
     * {@link PermissionAnnotationMethodInterceptor PermissionAnnotationMethodInterceptor} to
     * support role and permission annotations automatically.
     * @return the method interceptors to execute for the annotated method.
     */
    public Collection<AuthorizingAnnotationMethodInterceptor> getMethodInterceptors() {
        return methodInterceptors;
    }

    /**
     * Sets the method interceptors to execute for the annotated method.
     * @param methodInterceptors the method interceptors to execute for the annotated method.
     * @see #getMethodInterceptors()
     */
    public void setMethodInterceptors(Collection<AuthorizingAnnotationMethodInterceptor> methodInterceptors) {
        this.methodInterceptors = methodInterceptors;
    }

    /**
     * Iterates over the internal {@link #getMethodInterceptors() methodInterceptors} collection, and for each one,
     * ensures that if the interceptor
     * {@link AuthorizingAnnotationMethodInterceptor#supports(org.apache.shiro.aop.MethodInvocation) supports}
     * the invocation, that the interceptor
     * {@link AuthorizingAnnotationMethodInterceptor#assertAuthorized(org.apache.shiro.aop.MethodInvocation) asserts}
     * that the invocation is authorized to proceed.
     */
    protected void assertAuthorized(MethodInvocation methodInvocation) throws AuthorizationException {
        //default implementation just ensures no deny votes are cast:
        Collection<AuthorizingAnnotationMethodInterceptor> aamis = getMethodInterceptors();
        if (aamis != null && !aamis.isEmpty()) {
            for (AuthorizingAnnotationMethodInterceptor aami : aamis) {
                if (aami.supports(methodInvocation)) {
                    aami.assertAuthorized(methodInvocation);
                }
            }
        }
    }
}
