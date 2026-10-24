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

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.aop.AnnotationHandler;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.config.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An AnnotationHandler that executes authorization (access control) behavior based on directive(s) found in a
 * JSR-175 Annotation.
 *
 * @since 0.9.0
 */
public abstract class AuthorizingAnnotationHandler extends AnnotationHandler {

    /**
     * Constructs an <code>AuthorizingAnnotationHandler</code> who processes annotations of the
     * specified type.  Immediately calls <code>super(annotationClass)</code>.
     *
     * @param annotationClass the type of annotation this handler will process.
     */
    public AuthorizingAnnotationHandler(Class<? extends Annotation> annotationClass) {
        super(annotationClass);
    }

    /**
     * Ensures the calling Subject is authorized to execute based on the directive(s) found in the given
     * annotation.
     * <p/>
     * As this is an AnnotationMethodInterceptor, the implementations of this method typically inspect the annotation
     * and perform a corresponding authorization check based.
     *
     * @param a the <code>Annotation</code> to check for performing an authorization check.
     * @throws org.apache.shiro.authz.AuthorizationException if the class/instance/method is not allowed to proceed/execute.
     */
    public abstract void assertAuthorized(Annotation a) throws AuthorizationException;

    /**
     * What to do with authorization configuration that names no permissions or roles, such as the {@code perms} and
     * {@code roles} filters without arguments, or {@code @RequiresPermissions({})}.
     * <p/>
     * Such configuration performs no check, which is almost always a mistake. By default a warning is logged and the
     * previous behavior is kept. If the {@value #STRICT_PROPERTY} system property is {@code true}, the
     * configuration is rejected with a {@link ConfigurationException} when the integration reads it at startup.
     *
     * @since 3.0.2
     */
    public static final class AuthorizationConfigPolicy {
        /**
         * System property that, when {@code true}, makes empty authorization configuration fail at startup
         * instead of only logging a warning. Also enables strict {@link org.apache.shiro.authz.permission.WildcardPermission}
         * parsing, rejecting empty or blank permission parts and subparts, including trailing separators.
         */
        private static final String STRICT_PROPERTY = "shiro.authz.strictConfig";
        @Getter @Setter
        // Setter is for testing only, to avoid having to set a system property in the test JVM.
        private static boolean strictParsing = Boolean.getBoolean(STRICT_PROPERTY);

        private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizingAnnotationHandler.class);
        private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

        private AuthorizationConfigPolicy() {
        }

        /**
         * Validates the permissions or roles of an authorization annotation. Annotations other than
         * {@link RequiresPermissions} and {@link RequiresRoles} are ignored.
         *
         * @param annotation the annotation found on a class or method
         * @throws ConfigurationException if the annotation is empty and {@link #isStrictParsing()}
         *                                is set
         */
        public static <T extends Annotation> T validate(T annotation) {
            if (annotation instanceof RequiresPermissions permissions) {
                validate(permissions.value(), "@RequiresPermissions");
            } else if (annotation instanceof RequiresRoles roles) {
                validate(roles.value(), "@RequiresRoles");
            }
            return annotation;
        }

        /**
         * Validates authorization annotations declared on a type and throughout its hierarchy,
         * including composed annotations.
         *
         * @param type the type whose annotations are validated
         * @return the validated type
         */
        public static Class<?> validateHierarchy(Class<?> type) {
            AnnotationHierarchy.hierarchy(type).stream()
                    .flatMap(declaring -> Stream.concat(Stream.of(declaring),
                            Arrays.stream(declaring.getDeclaredMethods())
                                    .filter(AnnotationHierarchy.USER_DECLARED_METHODS)))
                    .forEach(element -> {
                        validate(AnnotationHierarchy.findDeclared(element, RequiresPermissions.class));
                        validate(AnnotationHierarchy.findDeclared(element, RequiresRoles.class));
                    });
            return type;
        }

        /**
         * Logs a warning, once per {@code what}, if the configuration is empty, and rejects it by throwing if
         * {@link #isStrictParsing()} is set. Integrations call this when they read the configuration
         * at startup, and the annotation handlers call it again when they check, for configuration that no
         * startup hook saw.
         *
         * @param values the configured permissions or roles
         * @param what   describes the configuration, for the message
         * @throws ConfigurationException if the configuration is empty and {@link #isStrictParsing()}
         *                                is set
         */
        public static void validate(String[] values, String what) {
            if (values != null && values.length > 0) {
                return;
            }
            boolean strict = isStrictParsing();
            if (WARNED.add(what)) {
                LOGGER.warn("{} specifies no permissions or roles, so it {}. Specify at least one.", what,
                        strict ? "is rejected" : "performs no check");
            }
            if (strict) {
                throw new ConfigurationException(what + " must specify at least one permission or role");
            }
        }
    }
}
