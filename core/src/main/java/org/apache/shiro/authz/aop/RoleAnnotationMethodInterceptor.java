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
import org.apache.shiro.authz.annotation.RequiresRoles;


/**
 * Checks to see if a @{@link RequiresRoles RequiresRoles} annotation is declared, and if so, performs
 * a role check to see if the calling <code>Subject</code> is allowed to invoke the method.
 *
 * @since 0.9
 */
public class RoleAnnotationMethodInterceptor extends AuthorizingAnnotationMethodInterceptor {

    /**
     * Default no-argument constructor that ensures this interceptor looks for
     * {@link RequiresRoles RequiresRoles} annotations in a method declaration.
     */
    public RoleAnnotationMethodInterceptor() {
        super( new RoleAnnotationHandler() );
    }

    /**
     * @param resolver
     * @since 1.1
     */
    public RoleAnnotationMethodInterceptor(AnnotationResolver resolver) {
        super(new RoleAnnotationHandler(), resolver);
    }
}
