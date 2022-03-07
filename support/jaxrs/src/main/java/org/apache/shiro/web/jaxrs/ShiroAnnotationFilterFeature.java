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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Wraps {@link AuthorizationFilter filters} around JAX-RS resources that are annotated with Shiro annotations.
 * @since 1.4
 */
public class ShiroAnnotationFilterFeature implements DynamicFeature {

    private static List<Class<? extends Annotation>> shiroAnnotations = Collections.unmodifiableList(Arrays.asList(
            RequiresPermissions.class,
            RequiresRoles.class,
            RequiresAuthentication.class,
            RequiresUser.class,
            RequiresGuest.class));

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {

        List<Annotation> authzSpecs = new ArrayList<Annotation>();

        for (Class<? extends Annotation> annotationClass : shiroAnnotations) {
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