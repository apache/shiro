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
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;


/**
 * Checks to see if a @{@link javax.annotation.security.RolesAllowed RolesAllowed} annotation is declared, and if so, performs
 * a role check to see if the calling <code>Subject</code> is allowed to invoke the method.
 *
 * @since 1.4.0
 */
public class JavaxSecurityRolesMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link javax.annotation.security.RolesAllowed RolesAllowed} annotations in a method declaration.
     */
    public JavaxSecurityRolesMethodInterceptor() {
        super( new JavaxSecurityRolesAnnotationHandler() );
    }

    /**
     * @param resolver
     * @since 1.4.0
     */
    public JavaxSecurityRolesMethodInterceptor(AnnotationResolver resolver) {
        super(new JavaxSecurityRolesAnnotationHandler(), resolver);
    }

    @Override
    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {

        DenyAll denyAllOnMethod = mi.getMethod().getAnnotation(DenyAll.class); // this can only be at the method level
        PermitAll permitAllOnMethod = mi.getMethod().getAnnotation(PermitAll.class); // a PermitAll on a class, is the default condition.
        RolesAllowed rolesAllowedOnMethod = mi.getMethod().getAnnotation(RolesAllowed.class);

        // DenyAll on the method take precedence over RolesAllowed and PermitAll
        if (denyAllOnMethod != null ) {
            throw new UnauthorizedException("Subject does not have access to method due to DenyAll annotation.");
        }

        // RolesAllowed on the method takes precedence over PermitAll
        if(rolesAllowedOnMethod != null) {
            super.assertAuthorized(mi);
            return;
        }

        // PermitAll on method takes precedence over RolesAllowed on the class
        if (permitAllOnMethod != null) {
            // just return
            return;
        }

        // DenyAll can't be attached to classes

        // RolesAllowed on the class takes precedence over PermitAll
        super.assertAuthorized(mi);
    }
}
