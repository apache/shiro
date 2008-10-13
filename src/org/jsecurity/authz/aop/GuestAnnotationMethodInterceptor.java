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

import org.jsecurity.aop.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.UnauthenticatedException;
import org.jsecurity.authz.annotation.RequiresGuest;

/**
 * Checks to see if a @{@link org.jsecurity.authz.annotation.RequiresGuest RequiresGuest} annotation
 * is declared, and if so, ensures the calling <code>Subject</code> does <em>not</em>
 * have an {@link org.jsecurity.subject.Subject#getPrincipal() identity} before invoking the method.
 * <p>
 * This annotation essentially ensures that <code>subject.{@link org.jsecurity.subject.Subject#getPrincipal() getPrincipal()} == null</code>.
 *
 * @author Les Hazlewood
 * @since 0.9.0 RC3
 */
public class GuestAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * @{@link org.jsecurity.authz.annotation.RequiresGuest RequiresGuest} annotations in a method
     * declaration.
     */
    public GuestAnnotationMethodInterceptor() {
        super(RequiresGuest.class);
    }

    /**
     * Ensures that the calling <code>Subject</code> is NOT a <em>user</em>, that is, they do not
     * have an {@link org.jsecurity.subject.Subject#getPrincipal() identity} before invoking the method.  If they are
     * a user ({@link org.jsecurity.subject.Subject#getPrincipal() Subject.getPrincipal()} != null), an
     * <code>AuthorizingException</code> will be thrown indicating the method is not allowed to be executed.
     *
     * @param mi the method invocation to check for one or more roles
     * @throws org.jsecurity.authz.AuthorizationException
     *          if the calling <code>Subject</code> is not a &quot;guest&quot;.
     */
    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        RequiresGuest annotation = (RequiresGuest) getAnnotation(mi);
        if (annotation != null) {
            if (getSubject().getPrincipal() != null) {
                throw new UnauthenticatedException("Attempting to access a guest-only method.  The current Subject is " +
                        "not a guest (they have been authenticated or remembered from a previous login).  Method " +
                        "invocation denied.");
            }
        }
    }
}
