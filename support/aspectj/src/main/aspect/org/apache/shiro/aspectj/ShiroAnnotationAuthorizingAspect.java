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
package org.apache.shiro.aspectj;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;

/**
 * Enforces Shiro's authorization annotations, such as {@code @RequiresPermissions}, on woven classes.
 * <p>
 * Shiro also recognizes them on interfaces and superclasses, and in composed annotations.
 * <p>
 * Every woven method is checked, which adds about 10 ns to each call of a method without Shiro annotations.
 * Weave only the code that needs it. With compile-time weaving, weave only the modules that use Shiro annotations.
 * With load-time weaving, limit the scope with {@code <include within="com.mycompany..*"/>}
 * in {@code META-INF/aop.xml}.
 */
@Aspect
public class ShiroAnnotationAuthorizingAspect {

    // Remembers per class whether a method has a Shiro annotation, so each hierarchy is searched only once.
    private static final ClassValue<Map<Method, Boolean>> REQUIRES_AUTHORIZATION = new ClassValue<>() {
        @Override
        protected Map<Method, Boolean> computeValue(Class<?> type) {
            return new ConcurrentHashMap<>();
        }
    };

    private static final String pointCutExpression =
            "execution(@org.apache.shiro.authz.annotation.RequiresAuthentication * *(..)) || " +
                    "execution(* (@org.apache.shiro.authz.annotation.RequiresAuthentication *).*(..)) || " +
                    "execution(@org.apache.shiro.authz.annotation.RequiresGuest * *(..)) || " +
                    "execution(* (@org.apache.shiro.authz.annotation.RequiresGuest *).*(..)) || " +
                    "execution(@org.apache.shiro.authz.annotation.RequiresPermissions * *(..)) || " +
                    "execution(* (@org.apache.shiro.authz.annotation.RequiresPermissions *).*(..)) || " +
                    "execution(@org.apache.shiro.authz.annotation.RequiresRoles * *(..)) || " +
                    "execution(* (@org.apache.shiro.authz.annotation.RequiresRoles *).*(..)) || " +
                    "execution(@org.apache.shiro.authz.annotation.RequiresUser * *(..)) || " +
                    "execution(* (@org.apache.shiro.authz.annotation.RequiresUser *).*(..))";

    @Pointcut(pointCutExpression)
    public void anyShiroAnnotatedMethod() {
    }

    // A pointcut only sees annotations on the method or class itself, so it cannot tell whether a method
    // inherits one. Match every method of the application and let AnnotationHierarchy decide.
    // Shiro's own classes are excluded so that Shiro does not check itself.
    @Pointcut("execution(* *(..)) && !within(org.apache.shiro..*)")
    void applicationMethod() {
    }

    @Pointcut("anyShiroAnnotatedMethod() || applicationMethod()")
    void mayRequireAuthorization() {
    }

    private AspectjAnnotationsAuthorizingMethodInterceptor interceptor =
            new AspectjAnnotationsAuthorizingMethodInterceptor();

    @Before("mayRequireAuthorization()")
    public void executeAnnotatedMethod(JoinPoint thisJoinPoint) throws Throwable {
        if (requiresAuthorization(thisJoinPoint)) {
            interceptor.performBeforeInterception(thisJoinPoint);
        }
    }

    private static boolean requiresAuthorization(JoinPoint joinPoint) {
        Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
        Object target = joinPoint.getTarget();
        Class<?> type = target != null ? target.getClass() : method.getDeclaringClass();
        return REQUIRES_AUTHORIZATION.get(type).computeIfAbsent(method, invoked ->
                AuthorizationAnnotations.shiroTypes().stream()
                        .anyMatch(annotation -> AnnotationHierarchy.findAnnotation(invoked, type, annotation) != null));
    }
}
