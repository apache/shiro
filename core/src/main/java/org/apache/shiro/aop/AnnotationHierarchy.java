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

import lombok.NonNull;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class AnnotationHierarchy {
    private static final String JAVA_LANG_ANNOTATION = "java.lang.annotation.";

    private static final ClassValue<Cache> CACHE = new ClassValue<>() {
        @Override
        protected Cache computeValue(@NonNull Class<?> type) {
            return new Cache(type);
        }
    };

    private AnnotationHierarchy() {
    }

    private record Key(Method method, Class<? extends Annotation> annotationType) { }

    private record Cache(List<Class<?>> hierarchy, Map<Key, Optional<Annotation>> found,
                         Map<Class<? extends Annotation>, Boolean> own) {
        Cache(Class<?> type) {
            this(AnnotationHierarchy.hierarchy(type).stream().filter(candidate -> candidate != Object.class).toList(),
                    new ConcurrentHashMap<>(), new ConcurrentHashMap<>());
        }
    }

    public static <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationType) {
        Class<?> searchRoot = targetClass != null ? targetClass : method.getDeclaringClass();
        Cache cache = cacheFor(searchRoot);
        return annotationType.cast(cache.found().computeIfAbsent(new Key(method, annotationType), key -> Optional.ofNullable(
                searchInvocation(method, searchRoot, cache.hierarchy(), annotationType))).orElse(null));
    }

    public static boolean isPresent(Class<?> targetClass, Class<? extends Annotation> annotationType) {
        return cacheFor(targetClass).hierarchy().stream().anyMatch(declaring -> cacheFor(declaring).own()
                .computeIfAbsent(annotationType, type -> findDeclared(declaring, type) != null
                        || Arrays.stream(declaring.getDeclaredMethods()).anyMatch(method -> !method.isBridge()
                        && !method.isSynthetic() && findDeclared(method, type) != null)));
    }

    static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType) {
        return findDeclared(element, annotationType, new HashSet<>());
    }

    private static <A extends Annotation> A searchInvocation(Method method, Class<?> targetClass,
                                                             List<Class<?>> hierarchy, Class<A> annotationType) {
        A annotation = findDeclared(method, annotationType);
        if (annotation != null || !isPresent(targetClass, annotationType)) {
            return annotation;
        }
        return hierarchy.stream().map(type -> declaredFor(type, method).map(declared -> findDeclared(declared, annotationType))
                .filter(Objects::nonNull).findFirst().or(() -> Optional.ofNullable(findDeclared(type, annotationType))))
                .flatMap(Optional::stream).findFirst().orElse(null);
    }

    static List<Class<?>> hierarchy(Class<?> type) {
        return Stream.<Class<?>>iterate(type, Objects::nonNull, Class::getSuperclass)
                .flatMap(AnnotationHierarchy::withInterfaces).distinct().toList();
    }

    private static Stream<Class<?>> withInterfaces(Class<?> type) {
        return Stream.concat(Stream.of(type), Arrays.stream(type.getInterfaces()).flatMap(AnnotationHierarchy::withInterfaces));
    }

    private static Stream<Method> declaredFor(Class<?> type, Method invoked) {
        Class<?>[] parameters = invoked.getParameterTypes();
        List<Method> candidates = Arrays.stream(type.getDeclaredMethods())
                .filter(candidate -> candidate.getName().equals(invoked.getName())
                        && !Modifier.isPrivate(candidate.getModifiers()) && !Modifier.isStatic(candidate.getModifiers())
                        && candidate.getParameterCount() == parameters.length && IntStream.range(0, parameters.length)
                        .allMatch(i -> candidate.getParameterTypes()[i].isAssignableFrom(parameters[i]))).toList();
        List<Method> exact = candidates.stream()
                .filter(candidate -> Arrays.equals(candidate.getParameterTypes(), parameters)).toList();
        return (exact.isEmpty() ? candidates : exact).stream();
    }

    private static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType,
                                                         Set<Class<? extends Annotation>> visited) {
        A annotation = element.getDeclaredAnnotation(annotationType);
        if (annotation != null) {
            return annotation;
        }
        return Arrays.stream(element.getDeclaredAnnotations()).map(Annotation::annotationType)
                .filter(metaType -> !metaType.getName().startsWith(JAVA_LANG_ANNOTATION) && visited.add(metaType))
                .map(metaType -> findDeclared(metaType, annotationType, visited))
                .filter(Objects::nonNull).findFirst().orElse(null);
    }

    private static Cache cacheFor(Class<?> type) {
        ClassLoader own = AnnotationHierarchy.class.getClassLoader();
        for (ClassLoader loader = type.getClassLoader(); loader != null; loader = loader.getParent()) {
            if (loader == own) {
                return CACHE.get(type);
            }
        }
        return own == null ? CACHE.get(type) : new Cache(type);
    }
}
