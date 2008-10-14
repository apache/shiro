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
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.annotation.RequiresPermissions;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.PermissionUtils;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * Checks to see if a @{@link org.jsecurity.authz.annotation.RequiresPermissions RequiresPermissions} annotation is
 * declared, and if so, performs a permission check to see if the calling <code>Subject</code> is allowed continued
 * access.
 *
 * @author Les Hazlewood
 * @since 0.9.0 RC3
 */
public class PermissionAnnotationHandler extends AuthorizingAnnotationHandler {

    /**
     * Default no-argument constructor that ensures this handler looks for
     * {@link org.jsecurity.authz.annotation.RequiresPermissions RequiresPermissions} annotations.
     */
    public PermissionAnnotationHandler() {
        super(RequiresPermissions.class);
    }

    /**
     * Returns the annotation {@link RequiresPermissions#value value}, from which the Permission will be constructed.
     *
     * @param a the RequiresPermissions annotation being inspected.
     * @return the annotation's <code>value</code>, from which the Permission will be constructed.
     */
    protected String getAnnotationValue(Annotation a) {
        RequiresPermissions rpAnnotation = (RequiresPermissions)a;
        return rpAnnotation.value();
    }

    /**
     * Ensures that the calling <code>Subject</code> has the Annotation's specified permissions, and if not, throws an
     * <code>AuthorizingException</code> indicating access is denied.
     *
     * @param a the RequiresPermission annotation being inspected to check for one or more permissions
     * @throws org.jsecurity.authz.AuthorizationException if the calling <code>Subject</code> does not have the permission(s) necessary to
     * continue access or execution.
     */
    public void assertAuthorized(Annotation a) throws AuthorizationException {
        if ( !(a instanceof RequiresPermissions) ) {
            return;
        }
        String p = getAnnotationValue(a);
        Set<String> perms = PermissionUtils.toPermissionStrings(p);

        Subject subject = getSubject();

        if (perms.size() == 1) {
            if (!subject.isPermitted(perms.iterator().next())) {
                String msg = "Calling Subject does not have required permission [" + p + "].  " +
                        "Method invocation denied.";
                throw new UnauthorizedException(msg);
            }
        } else {
            String[] permStrings = new String[perms.size()];
            permStrings = perms.toArray(permStrings);
            if (!subject.isPermittedAll(permStrings)) {
                String msg = "Calling Subject does not have required permissions [" + p + "].  " +
                        "Method invocation denied.";
                throw new UnauthorizedException(msg);
            }

        }
    }
}
