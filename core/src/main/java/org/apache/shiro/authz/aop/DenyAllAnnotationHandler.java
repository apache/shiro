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

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;

import javax.annotation.security.DenyAll;
import java.lang.annotation.Annotation;

/**
 * This {@link org.apache.shiro.aop.AnnotationHandler AnnotationHandler} denys access from any subject
 * (anonymous or logged in user).
 *
 * @since 1.5.0
 */
public class DenyAllAnnotationHandler extends AuthorizingAnnotationHandler {


    /**
     * Default no-argument constructor that ensures this interceptor looks for
     *
     * {@link org.apache.shiro.authz.annotation.RequiresGuest RequiresGuest} annotations in a method
     * declaration.
     */
    public DenyAllAnnotationHandler() {
        super(DenyAll.class);
    }

    /**
     * Causes a {@link UnauthorizedException} to be thrown if a DenyAll annotation is present.
     *
     * @param a the annotation to check for one or more roles
     * @throws UnauthorizedException when the DenyAll annotation is present
     */
    public void assertAuthorized(Annotation a) throws UnauthorizedException {
//        if (!(a instanceof DenyAll)) return;

        throw new UnauthenticatedException("Attempting to perform a denied operation.");
    }
}
