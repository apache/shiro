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

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.UnauthenticatedException;
import org.jsecurity.authz.annotation.RequiresUser;

import java.lang.annotation.Annotation;

/**
 * Checks to see if a @{@link org.jsecurity.authz.annotation.RequiresUser RequiresUser} annotation
 * is declared, and if so, ensures the calling <code>Subject</code> is <em>either</em>
 * {@link org.jsecurity.subject.Subject#isAuthenticated() authenticated} <b><em>or</em></b> remembered via remember
 * me services before allowing access.
 * <p>
 * This annotation essentially ensures that <code>subject.{@link org.jsecurity.subject.Subject#getPrincipal() getPrincipal()} != null</code>.
 *
 * @author Les Hazlewood
 * @since 0.9.0 RC3
 */
public class UserAnnotationHandler extends AuthorizingAnnotationHandler {

    /**
     * Default no-argument constructor that ensures this handler looks for
     *
     * {@link org.jsecurity.authz.annotation.RequiresUser RequiresUser} annotations.
     */
    public UserAnnotationHandler() {
        super(RequiresUser.class);
    }

    /**
     * Ensures that the calling <code>Subject</code> is a <em>user</em>, that is, they are <em>either</code>
     * {@link org.jsecurity.subject.Subject#isAuthenticated() authenticated} <b><em>or</em></b> remembered via remember
     * me services before allowing access, and if not, throws an
     * <code>AuthorizingException</code> indicating access is not allowed.
     *
     * @param a the RequiresUser annotation to check
     * @throws org.jsecurity.authz.AuthorizationException
     *         if the calling <code>Subject</code> is not authenticated or remembered via rememberMe services.
     */
    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if (a instanceof RequiresUser && getSubject().getPrincipal() == null) {
            throw new UnauthenticatedException("Attempting to perform a user-only operation.  The current Subject is " +
                    "not a user (they haven't been authenticated or remembered from a previous login).  " +
                    "Access denied.");
        }
    }
}
