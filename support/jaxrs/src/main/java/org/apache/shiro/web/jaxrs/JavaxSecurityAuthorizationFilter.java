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

import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;
import org.apache.shiro.authz.aop.JavaxSecurityRolesAnnotationHandler;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * A filter that grants or denies access to a JAX-RS resource based on the <code>javax.annotation.security</code> annotations on it.
 *
 * @see org.apache.shiro.authz.annotation
 * @since 1.4
 */
public class JavaxSecurityAuthorizationFilter implements ContainerRequestFilter {

    private final Map<AuthorizingAnnotationHandler, Annotation> authzChecks;

    public JavaxSecurityAuthorizationFilter(Collection<Annotation> authzSpecs) {
        Map<AuthorizingAnnotationHandler, Annotation> authChecks = new HashMap<AuthorizingAnnotationHandler, Annotation>(authzSpecs.size());
        for (Annotation authSpec : authzSpecs) {
            authChecks.put(createHandler(authSpec), authSpec);
        }
        this.authzChecks = Collections.unmodifiableMap(authChecks);
    }

    private static AuthorizingAnnotationHandler createHandler(Annotation annotation) {
        Class<?> t = annotation.annotationType();

        if (RolesAllowed.class.equals(t) || DenyAll.class.equals(t) || PermitAll.class.equals(t)) {
            return new JavaxSecurityRolesAnnotationHandler();
        }

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