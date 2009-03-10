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
package org.ki.authz.aop;

/**
 * Checks to see if a @{@link org.ki.authz.annotation.RequiresGuest RequiresGuest} annotation
 * is declared, and if so, ensures the calling <code>Subject</code> does <em>not</em>
 * have an {@link org.ki.subject.Subject#getPrincipal() identity} before invoking the method.
 * <p>
 * This annotation essentially ensures that <code>subject.{@link org.ki.subject.Subject#getPrincipal() getPrincipal()} == null</code>.
 *
 * @author Les Hazlewood
 * @since 0.9.0
 */
public class GuestAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link org.ki.authz.annotation.RequiresGuest RequiresGuest} annotations in a method
     * declaration.
     */
    public GuestAnnotationMethodInterceptor() {
        super(new GuestAnnotationHandler());
    }
}
