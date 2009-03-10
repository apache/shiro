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

import org.ki.authz.AuthorizationException;
import org.ki.authz.UnauthenticatedException;
import org.ki.authz.annotation.RequiresGuest;

import java.lang.annotation.Annotation;

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
public class GuestAnnotationHandler extends AuthorizingAnnotationHandler {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     *
     * {@link org.ki.authz.annotation.RequiresGuest RequiresGuest} annotations in a method
     * declaration.
     */
    public GuestAnnotationHandler() {
        super(RequiresGuest.class);
    }

    /**
     * Ensures that the calling <code>Subject</code> is NOT a <em>user</em>, that is, they do not
     * have an {@link org.ki.subject.Subject#getPrincipal() identity} before continuing.  If they are
     * a user ({@link org.ki.subject.Subject#getPrincipal() Subject.getPrincipal()} != null), an
     * <code>AuthorizingException</code> will be thrown indicating that execution is not allowed to continue.
     *
     * @param a the annotation to check for one or more roles
     * @throws org.ki.authz.AuthorizationException
     *          if the calling <code>Subject</code> is not a &quot;guest&quot;.
     */
    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (a instanceof RequiresGuest && getSubject().getPrincipal() != null) {
            throw new UnauthenticatedException("Attempting to perform a guest-only operation.  The current Subject is " +
                    "not a guest (they have been authenticated or remembered from a previous login).  Access " +
                    "denied.");
        }
    }
}
