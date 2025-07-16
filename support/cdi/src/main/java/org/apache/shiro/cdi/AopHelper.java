package org.apache.shiro.cdi;

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

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthenticatedAnnotationHandler;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler;
import org.apache.shiro.authz.aop.DenyAllAnnotationHandler;
import org.apache.shiro.authz.aop.GuestAnnotationHandler;
import org.apache.shiro.authz.aop.PermissionAnnotationHandler;
import org.apache.shiro.authz.aop.PermitAllAnnotationHandler;
import org.apache.shiro.authz.aop.RoleAnnotationHandler;
import org.apache.shiro.authz.aop.RolesAllowedAnnotationHandler;
import org.apache.shiro.authz.aop.UserAnnotationHandler;

/**
 * Security decorator instantiation helper
 */
@SuppressWarnings("HideUtilityClassConstructor")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
class AopHelper {
    /**
     * List annotations classes which can be applied (either method or a class).
     */
    @SuppressWarnings("ConstantName")
    static final Map<Class<? extends Annotation>, Callable<AuthorizingAnnotationHandler>> authorizationAnnotationClasses
            = Map.of(
            RequiresPermissions.class, PermissionAnnotationHandler::new,
            RequiresRoles.class, RoleAnnotationHandler::new,
            RequiresUser.class, UserAnnotationHandler::new,
            RequiresGuest.class, GuestAnnotationHandler::new,
            RequiresAuthentication.class, AuthenticatedAnnotationHandler::new,
            RolesAllowed.class, RolesAllowedAnnotationHandler::new,
            PermitAll.class, PermitAllAnnotationHandler::new,
            DenyAll.class, DenyAllAnnotationHandler::new);

    /**
     * Create list of
     * {@link SecurityInterceptor}
     * instances for method. This method search all method and class annotations
     * and use annotation data for create interceptors.
     * <p>
     * This method considers only those annotations that have been declared in
     * the set through parameters of the method and class, regardless of the
     * inheritance or interface implementations
     *
     * @param method
     * @param clazz
     * @return
     */
    static List<SecurityInterceptor> createSecurityInterceptors(Method method, Class<?> clazz) {
        List<SecurityInterceptor> result = new ArrayList<>();

        if (isInterceptOnClassAnnotation(method.getModifiers())) {
            for (Class<? extends Annotation> ac
                    : getAuthorizationAnnotationClasses()) {
                Annotation annotationOnClass = clazz.getAnnotation(ac);
                if (annotationOnClass != null) {
                    result.add(new SecurityInterceptor(annotationOnClass));
                }
            }
        }

        for (Class<? extends Annotation> ac
                : getAuthorizationAnnotationClasses()) {
            Annotation annotation = method.getAnnotation(ac);
            if (annotation != null) {
                result.add(new SecurityInterceptor(annotation));
            }
        }

        return result;
    }

    /**
     * Create {@link org.apache.shiro.authz.aop.AuthorizingAnnotationHandler}
     * for annotation.
     *
     * @param annotation
     * @return
     */
    @SneakyThrows
    static AuthorizingAnnotationHandler createHandler(Annotation annotation) {
        return authorizationAnnotationClasses.get(annotation.annotationType()).call();
    }

    /**
     * Rule under which determined the fate of the class contains annotation.
     * <p/>
     * All public and protected methods.
     *
     * @param modifiers
     * @return
     */
    private static boolean isInterceptOnClassAnnotation(int modifiers) {
        return Modifier.isPublic(modifiers)
                || Modifier.isProtected(modifiers);
    }

    private static Collection<Class<? extends Annotation>> getAuthorizationAnnotationClasses() {
        return authorizationAnnotationClasses.keySet();
    }

    @RequiredArgsConstructor
    static class SecurityInterceptor {
        private final AuthorizingAnnotationHandler handler;
        private final @Getter Annotation annotation;

        /**
         * Initialize {@link #handler} field use annotation.
         *
         * @param annotation annotation for create handler and use during
         *                   {@link #intercept()} invocation.
         */
        SecurityInterceptor(Annotation annotation) {
            this.annotation = annotation;
            this.handler = AopHelper.createHandler(annotation);
            if (handler == null) {
                throw new IllegalStateException("No handler for " + annotation + "annotation");
            }
        }

        void intercept() {
            handler.assertAuthorized(getAnnotation());
        }
    }
}
