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

import org.apache.shiro.aop.AnnotationResolver;

/**
 * Checks to see if a @{@link org.apache.shiro.authz.annotation.RequiresAuthentication RequiresAuthenticated} annotation
 * is declared, and if so, ensures the calling
 * <code>Subject</code>.{@link org.apache.shiro.subject.Subject#isAuthenticated() isAuthenticated()} before invoking
 * the method.
 *
 * @since 0.9.0
 */
public class AuthenticatedAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link org.apache.shiro.authz.annotation.RequiresAuthentication RequiresAuthentication} annotations in a method
     * declaration.
     */
    public AuthenticatedAnnotationMethodInterceptor() {
        super(new AuthenticatedAnnotationHandler());
    }

    /**
     * @param resolver
     * @since 1.1
     */
    public AuthenticatedAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new AuthenticatedAnnotationHandler(), resolver);
    }
}
