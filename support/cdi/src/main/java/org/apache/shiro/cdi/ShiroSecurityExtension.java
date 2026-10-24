/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi;

import java.lang.annotation.Annotation;
import java.util.stream.Stream;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.NormalScope;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Stereotype;
import jakarta.enterprise.inject.spi.Extension;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;
import jakarta.enterprise.inject.spi.WithAnnotations;
import jakarta.inject.Scope;

import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;

/**
 * Automatically apply Shiro security to all appropriate beans.
 * <p>
 * The observer fires only for types that carry an authorization annotation or a bean-defining annotation
 * (a scope or a stereotype), so unrelated classes are never inspected. Of those, every type secured anywhere in
 * its hierarchy (itself, its superclasses or its interfaces) gets the interceptor binding.
 */
public class ShiroSecurityExtension implements Extension {
    @ShiroSecureAnnotation
    public static class ShiroSecureAnnotated {
    }

    private static final Annotation SHIRO_SECURE = ShiroSecureAnnotated.class.getDeclaredAnnotations()[0];

    public <T> void addSecurity(@Observes @WithAnnotations({
            RequiresAuthentication.class, RequiresGuest.class, RequiresPermissions.class,
            RequiresRoles.class, RequiresUser.class, RolesAllowed.class,
            PermitAll.class, DenyAll.class}) ProcessAnnotatedType<T> pat) {
        pat.getAnnotatedType().getAnnotations().forEach(AuthorizationConfigPolicy::validate);
        pat.getAnnotatedType().getMethods().forEach(method ->
                method.getAnnotations().forEach(AuthorizationConfigPolicy::validate));
        pat.setAnnotatedType(new AnnotatedTypeWrapper<>(pat.getAnnotatedType(), SHIRO_SECURE));
    }

    /**
     * A bean with a scope or stereotype is secured if a superclass or an interface is.
     * The bean's own annotations are not inspected, the observer above already handles them.
     */
    public <T> void addInheritedSecurity(@Observes @WithAnnotations({
            Scope.class, NormalScope.class, Stereotype.class}) ProcessAnnotatedType<T> pat) {
        applyInheritedSecurity(pat);
    }

    /**
     * Adds the security interceptor binding to the type if a superclass or an interface is secured, and validates
     * the authorization configuration across that hierarchy. Lets other bean-defining annotations, such as the EJB
     * ones, reuse the same rule.
     *
     * @param pat the type being processed
     * @param <T> type of the processed class
     */
    public static <T> void applyInheritedSecurity(ProcessAnnotatedType<T> pat) {
        Class<?> type = pat.getAnnotatedType().getJavaClass();
        if (Stream.concat(Stream.of(type.getSuperclass()), Stream.of(type.getInterfaces()))
                .filter(parent -> parent != null && parent != Object.class)
                .anyMatch(parent -> AuthorizationAnnotations.allTypes().stream()
                        .anyMatch(annotation -> AnnotationHierarchy.isPresent(parent, annotation)))) {
            AuthorizationConfigPolicy.validateHierarchy(type);
            pat.setAnnotatedType(new AnnotatedTypeWrapper<>(pat.getAnnotatedType(), SHIRO_SECURE));
        }
    }
}
