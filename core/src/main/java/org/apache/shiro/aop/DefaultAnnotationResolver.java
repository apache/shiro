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
package org.apache.shiro.aop;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Objects;

/**
 * Default {@code AnnotationResolver} implementation that locates the annotation through
 * {@link AnnotationHierarchy}: on the invoked method, on the same method declared by any superclass or
 * interface of the target object's class, and finally on the target class, its superclasses and interfaces,
 * taking meta-annotations (composed annotations) into account at every step.
 *
 * @since 1.1
 */
public class DefaultAnnotationResolver implements AnnotationResolver {

    /**
     * Returns the annotation governing the invocation, see {@link AnnotationHierarchy#findAnnotation(Method, Class, Class)}.
     *
     * @param mi    the intercepted method to be invoked.
     * @param clazz the annotation class to use to find an annotation instance on the method.
     * @return the discovered annotation or {@code null} if an annotation instance could not be
     * found.
     */
    @Override
    public Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz) {
        if (mi == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }
        Method m = mi.getMethod();
        if (m == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);
        }
        Object target = mi.getThis();
        return AnnotationHierarchy.findAnnotation(m, target != null ? target.getClass() : null, clazz);
    }

    /**
     * @param targetClass the class to inspect
     * @param clazz       the annotation type
     * @return the type-level annotation found on the class, its superclasses or interfaces
     * @deprecated use {@link #getAnnotation(MethodInvocation, Class)}
     */
    @Deprecated(since = "3.0.2")
    public static Annotation getAnnotationFromClassHierarchy(Class<?> targetClass, Class<? extends Annotation> clazz) {
        return AnnotationHierarchy.hierarchy(targetClass).stream()
                .map(type -> AnnotationHierarchy.findDeclared(type, clazz)).filter(Objects::nonNull).findFirst().orElse(null);
    }
}
