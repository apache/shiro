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
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.ws.rs.Priorities;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import static org.apache.shiro.web.jaxrs.SubjectPrincipalRequestFilter.SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM;

/**
 * Wraps {@link AuthorizationFilter filters} around JAX-RS resources that are annotated with Shiro annotations.
 * @since 1.4
 */
public class ShiroAnnotationFilterFeature implements DynamicFeature {
    private static final List<Class<? extends Annotation>> shiroAnnotations = List.of(
            RequiresPermissions.class,
            RequiresRoles.class,
            RequiresAuthentication.class,
            RequiresUser.class,
            RequiresGuest.class);
    private static final List<Class<? extends Annotation>> jsr250Annotations = List.of(
            RolesAllowed.class, PermitAll.class, DenyAll.class);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        List<Annotation> authzSpecs = new ArrayList<>();
        var annotations = shiroAnnotations;
        if (Boolean.TRUE.equals(context.getConfiguration().getProperty(SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM))) {
            annotations = Stream.concat(shiroAnnotations.stream(), jsr250Annotations.stream())
                    .collect(Collectors.toList());
        }

        for (Class<? extends Annotation> annotationClass : annotations) {
            // XXX What is the performance of getAnnotation vs getAnnotations?
            Annotation classAuthzSpec = resourceInfo.getResourceClass().getAnnotation(annotationClass);
            Annotation methodAuthzSpec = resourceInfo.getResourceMethod().getAnnotation(annotationClass);

            if (classAuthzSpec != null) authzSpecs.add(classAuthzSpec);
            if (methodAuthzSpec != null) authzSpecs.add(methodAuthzSpec);
        }

        if (!authzSpecs.isEmpty()) {
            context.register(new AnnotationAuthorizationFilter(authzSpecs), Priorities.AUTHORIZATION);
        }
    }
}
