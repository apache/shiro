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
package org.jsecurity.authz.aop;

import org.jsecurity.aop.AnnotationMethodInterceptor;
import org.jsecurity.aop.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;

import java.lang.annotation.Annotation;

/**
 * An <tt>AnnotationMethodInterceptor</tt> that asserts the calling code is authorized to execute the method
 * before allowing the invocation to continue by inspecting code annotations to perform an access control check.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public abstract class AuthorizingAnnotationMethodInterceptor extends AnnotationMethodInterceptor {

    /**
     * Default constructor that merely calls {@link org.jsecurity.aop.AnnotationMethodInterceptor super(annotationClass)}
     * @param annotationClass the specific annotatation class this interceptor will look for when performing an
     * authorization check.
     */
    public AuthorizingAnnotationMethodInterceptor(Class<? extends Annotation> annotationClass) {
        super(annotationClass);
    }

    /**
     * Ensures the <code>methodInvocation</code> is allowed to execute first before proceeding by calling the
     * {@link #assertAuthorized(org.jsecurity.aop.MethodInvocation) assertAuthorized} method first.
     *
     * @param methodInvocation the method invocation to check for authorization prior to allowing it to proceed/execute.
     * @return the return value from the method invocation (the value of {@link org.jsecurity.aop.MethodInvocation#proceed() MethodInvocation.proceed()}).
     * @throws AuthorizationException if the <code>MethodInvocation</code> is not allowed to proceed.
     * @throws Throwable if any other error occurs.
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        assertAuthorized(methodInvocation);
        return methodInvocation.proceed();
    }

    /**
     * Ensures the calling Subject is authorized to execute the specified <code>MethodInvocation</code>.
     * <p/>
     * As this is an AnnotationMethodInterceptor, the implementations of this method typically inspect the method to
     * see if it has a specific Annotation, and if it does, performs an authorization check based on the information
     * defined by the Annotation.
     *
     * @param mi the <code>MethodInvocation</code> to check to see if it is allowed to proceed/execute.
     * @throws AuthorizationException if the method invocation is not allowed to continue/execute.
     */
    public abstract void assertAuthorized(MethodInvocation mi) throws AuthorizationException;
}
