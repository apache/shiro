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

import java.lang.annotation.Annotation;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.RequiresAuthentication;


/**
 * Handles {@link RequiresAuthentication RequiresAuthentication} annotations and ensures the calling subject is
 * authenticated before allowing access.
 *
 * @since 0.9.0
 */
public class AuthenticatedAnnotationHandler extends AuthorizingAnnotationHandler {

    /**
     * Default no-argument constructor that ensures this handler to process
     * {@link org.apache.shiro.authz.annotation.RequiresAuthentication RequiresAuthentication} annotations.
     */
    public AuthenticatedAnnotationHandler() {
        super(RequiresAuthentication.class);
    }

    /**
     * Ensures that the calling <code>Subject</code> is authenticated, and if not, throws an
     * {@link org.apache.shiro.authz.UnauthenticatedException UnauthenticatedException} indicating the method is not allowed to be executed.
     *
     * @param a the annotation to inspect
     * @throws org.apache.shiro.authz.UnauthenticatedException if the calling <code>Subject</code> has not yet
     * authenticated.
     */
    public void assertAuthorized(Annotation a) throws UnauthenticatedException {
        if (a instanceof RequiresAuthentication && !getSubject().isAuthenticated() ) {
            throw new UnauthenticatedException( "The current Subject is not authenticated.  Access denied." );
        }
    }
}
