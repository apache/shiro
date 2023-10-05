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

import javax.annotation.security.PermitAll;
import java.lang.annotation.Annotation;

/**
 * This {@link org.apache.shiro.aop.AnnotationHandler AnnotationHandler} allows access from any subject
 * (anonymous or logged in user).  It is largely a no-op or for documentation. However, this annotation WILL override
 * a {@link javax.annotation.security.DenyAll DenyAll} or {@link javax.annotation.security.RolesAllowed RolesAllowed}
 * annotation if those annotations are placed at the class level and {@link PermitAll} is placed on a method.
 *
 * @since 2.0
 */
public class PermitAllAnnotationHandler extends AuthorizingAnnotationHandler {
    /**
     * Default no-argument constructor that ensures this interceptor looks for a {@link PermitAll}
     * annotation in a method declaration.
     */
    public PermitAllAnnotationHandler() {
        super(PermitAll.class);
    }

    /**
     * No-op, the {@link PermitAll} annotation allows all subjects (including guests/anonymous).
     *
     * @param a the annotation to check for one or more roles
     */
    @Override
    public void assertAuthorized(Annotation a) {
    }
}
