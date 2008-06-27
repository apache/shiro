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
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.authz.annotation.RequiresRoles;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class RoleAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    public RoleAnnotationMethodInterceptor() {
        setAnnotationClass(RequiresRoles.class);
        init();
    }

    public void assertAuthorized(MethodInvocation mi) throws AuthorizationException {
        RequiresRoles rrAnnotation = (RequiresRoles) getAnnotation(mi);

        String roleId = rrAnnotation.value();

        String[] roles = roleId.split(",");

        if (roles.length == 1) {
            if (!getSubject().hasRole(roles[0])) {
                String msg = "Calling Subject does not have required role [" + roleId + "].  " +
                        "MethodInvocation denied.";
                throw new UnauthorizedException(msg);
            }
        } else {
            Set<String> rolesSet = new LinkedHashSet<String>(Arrays.asList(roles));
            if (!getSubject().hasAllRoles(rolesSet)) {
                String msg = "Calling Subject does not have required roles [" + roleId + "].  " +
                        "MethodInvocation denied.";
                throw new UnauthorizedException(msg);
            }
        }
    }
}
