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
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.lang.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

public final class AuthorizationAnnotations {
    private static final String JSR250_PROBE = "jakarta.annotation.security.RolesAllowed";

    private static final List<Registration> SHIRO = List.of(
            new Registration(RequiresRoles.class, RoleAnnotationMethodInterceptor::new),
            new Registration(RequiresPermissions.class, PermissionAnnotationMethodInterceptor::new),
            new Registration(RequiresAuthentication.class, AuthenticatedAnnotationMethodInterceptor::new),
            new Registration(RequiresUser.class, UserAnnotationMethodInterceptor::new),
            new Registration(RequiresGuest.class, GuestAnnotationMethodInterceptor::new));

    private static final List<Registration> ALL = Stream.concat(SHIRO.stream(),
            !ClassUtils.isAvailable(JSR250_PROBE) ? Stream.empty() : Stream.of(
            new Registration(jakarta.annotation.security.RolesAllowed.class, interceptorFor(RolesAllowedAnnotationHandler::new)),
            new Registration(jakarta.annotation.security.PermitAll.class, interceptorFor(PermitAllAnnotationHandler::new)),
            new Registration(jakarta.annotation.security.DenyAll.class, interceptorFor(DenyAllAnnotationHandler::new))))
            .toList();

    private static final List<Class<? extends Annotation>> SHIRO_TYPES =
            SHIRO.stream().<Class<? extends Annotation>>map(Registration::type).toList();

    private static final List<Class<? extends Annotation>> ALL_TYPES =
            ALL.stream().<Class<? extends Annotation>>map(Registration::type).toList();

    private AuthorizationAnnotations() {
    }

    private interface Factory extends Function<AnnotationResolver, AuthorizingAnnotationMethodInterceptor> {
    }

    private record Registration(Class<? extends Annotation> type, Factory factory) { }

    public static List<Class<? extends Annotation>> shiroTypes() {
        return SHIRO_TYPES;
    }

    public static List<Class<? extends Annotation>> allTypes() {
        return ALL_TYPES;
    }

    public static List<AuthorizingAnnotationMethodInterceptor> createMethodInterceptors(
            AnnotationResolver resolver, Collection<Class<? extends Annotation>> annotationTypes) {
        return annotationTypes.stream().map(type -> ALL.stream().filter(registration -> registration.type() == type)
                .findFirst().orElseThrow(() -> new IllegalArgumentException(
                        "Cannot create a handler for the unknown annotation " + type)).factory().apply(resolver)).toList();
    }

    private static Factory interceptorFor(Supplier<AuthorizingAnnotationHandler> handler) {
        return resolver -> new AuthorizingAnnotationMethodInterceptor(handler.get(), resolver) { };
    }
}
