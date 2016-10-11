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
package org.apache.shiro.web.jaxrs;


import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthenticatedAnnotationHandler;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;
import org.apache.shiro.authz.aop.GuestAnnotationHandler;
import org.apache.shiro.authz.aop.PermissionAnnotationHandler;
import org.apache.shiro.authz.aop.RoleAnnotationHandler;
import org.apache.shiro.authz.aop.UserAnnotationHandler;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A filter that grants or denies access to a JAX-RS resource based on the Shiro annotations on it.
 *
 * @see org.apache.shiro.authz.annotation
 * @since 1.4
 */
public class AnnotationAuthorizationFilter implements ContainerRequestFilter {

    private final Map<AuthorizingAnnotationHandler, Annotation> authzChecks;

    public AnnotationAuthorizationFilter(Collection<Annotation> authzSpecs) {
        Map<AuthorizingAnnotationHandler, Annotation> authChecks = new HashMap<AuthorizingAnnotationHandler, Annotation>(authzSpecs.size());
        for (Annotation authSpec : authzSpecs) {
            authChecks.put(createHandler(authSpec), authSpec);
        }
        this.authzChecks = Collections.unmodifiableMap(authChecks);
    }

    private static AuthorizingAnnotationHandler createHandler(Annotation annotation) {
        Class<?> t = annotation.annotationType();
        if (RequiresPermissions.class.equals(t)) return new PermissionAnnotationHandler();
        else if (RequiresRoles.class.equals(t)) return new RoleAnnotationHandler();
        else if (RequiresUser.class.equals(t)) return new UserAnnotationHandler();
        else if (RequiresGuest.class.equals(t)) return new GuestAnnotationHandler();
        else if (RequiresAuthentication.class.equals(t)) return new AuthenticatedAnnotationHandler();
        else throw new IllegalArgumentException("Cannot create a handler for the unknown for annotation " + t);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        for (Map.Entry<AuthorizingAnnotationHandler, Annotation> authzCheck : authzChecks.entrySet()) {
            AuthorizingAnnotationHandler handler = authzCheck.getKey();
            Annotation authzSpec = authzCheck.getValue();
            handler.assertAuthorized(authzSpec);
        }
    }

}