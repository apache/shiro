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


import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.DynamicFeature;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.FeatureContext;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.apache.shiro.web.jaxrs.SubjectPrincipalRequestFilter.SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM;

/**
 * Wraps {@link AuthorizationFilter filters} around JAX-RS resources that are annotated with Shiro annotations.
 *
 * @since 1.4
 */
public class ShiroAnnotationFilterFeature implements DynamicFeature {

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        List<Annotation> authzSpecs = new ArrayList<>();
        Collection<Class<? extends Annotation>> annotations = AuthorizationAnnotations.shiroTypes();
        if (Boolean.TRUE.equals(context.getConfiguration().getProperty(SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM))) {
            annotations = AuthorizationAnnotations.allTypes();
        }

        for (Class<? extends Annotation> annotationClass : annotations) {
            Annotation authzSpec = AnnotationHierarchy.findAnnotation(resourceInfo.getResourceMethod(),
                    resourceInfo.getResourceClass(), annotationClass);
            if (authzSpec != null) {
                authzSpecs.add(authzSpec);
            }
        }

        if (!authzSpecs.isEmpty()) {
            context.register(new AnnotationAuthorizationFilter(authzSpecs), Priorities.AUTHORIZATION);
        }
    }
}
