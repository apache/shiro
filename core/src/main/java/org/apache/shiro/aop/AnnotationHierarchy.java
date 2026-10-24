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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.IntStream;
import java.util.stream.Stream;


public final class AnnotationHierarchy {

    public static final Predicate<Method> USER_DECLARED_METHODS = method -> !method.isBridge() && !method.isSynthetic();

    private static final ClassLoader OWN_LOADER = AnnotationHierarchy.class.getClassLoader();

    private static final ClassValue<Cache> CACHE = new ClassValue<>() {
        @Override
        protected Cache computeValue(@NonNull Class<?> type) {
            return new Cache(type);
        }
    };

    /**
     * Results for classes that can't hold a {@link ClassValue} entry (see {@link #cacheFor(Class)}),
     * such as the JDK's and the platform's. Keys are weak, and the values only refer to annotation types
     * that this class's loader keeps alive anyway (see {@link #ownFor(Class, Class)}), so nothing is pinned.
     */
    private static final Map<Class<?>, Map<Class<? extends Annotation>, Boolean>> FOREIGN_OWN =
            Collections.synchronizedMap(new WeakHashMap<>());

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
        return cacheFor(targetClass).hierarchy().stream().anyMatch(declaring -> ownFor(declaring, annotationType)
                .computeIfAbsent(annotationType, type -> findDeclared(declaring, type) != null
                        || Arrays.stream(declaring.getDeclaredMethods()).filter(USER_DECLARED_METHODS)
                        .anyMatch(method -> findDeclared(method, type) != null)));
    }


    public static <A extends Annotation> A findDeclared(AnnotatedElement element, Class<A> annotationType) {
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


    public static List<Class<?>> hierarchy(Class<?> type) {
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
                .filter(metaType -> !metaType.getName().startsWith("java.lang.annotation.") && visited.add(metaType))
                .map(metaType -> findDeclared(metaType, annotationType, visited))
                .filter(Objects::nonNull).findFirst().orElse(null);
    }


    private static Cache cacheFor(Class<?> type) {
        return isSelfOrAncestor(OWN_LOADER, type.getClassLoader()) ? CACHE.get(type) : new Cache(type);
    }

    /**
     * Returns where to remember whether the class declares the annotation. Classes that can't hold a
     * {@link ClassValue} entry, such as the JDK's and the platform's, are shared by every bean and would otherwise
     * be searched again on each lookup. Their results are kept in {@link #FOREIGN_OWN}, unless the annotation type
     * could be unloaded before this class, in which case nothing is remembered.
     */
    private static Map<Class<? extends Annotation>, Boolean> ownFor(Class<?> declaring,
                                                                    Class<? extends Annotation> annotationType) {
        if (isSelfOrAncestor(OWN_LOADER, declaring.getClassLoader())) {
            return CACHE.get(declaring).own();
        }
        return isSelfOrAncestor(annotationType.getClassLoader(), OWN_LOADER)
                ? FOREIGN_OWN.computeIfAbsent(declaring, key -> new ConcurrentHashMap<>()) : new HashMap<>();
    }

    private static boolean isSelfOrAncestor(ClassLoader ancestor, ClassLoader loader) {
        return Stream.iterate(loader, Objects::nonNull, ClassLoader::getParent).anyMatch(parent -> parent == ancestor);
    }
}
