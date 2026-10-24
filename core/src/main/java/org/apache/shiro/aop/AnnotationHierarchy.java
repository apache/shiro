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

/**
 * Framework-independent, cached discovery of annotations across a type hierarchy.
 * <p>
 * The lookup rules are the same for every Shiro integration (Spring, Guice, CDI, JAX-RS, AspectJ).
 * The closest declaration wins.
 * The invoked method itself is inspected first.
 * Then every type of the target's hierarchy is inspected, most specific first: the target class,
 * its interfaces, its superclass and so on.
 * At each type, the method it overrides or implements is inspected before the type itself.
 * So a method-level annotation overrides a type-level annotation of the same type declared at the same level
 * or further up.
 * A subclass can also restrict inherited methods with a type-level annotation.
 * At every step the annotation may be present directly or as a meta-annotation (composed annotation).
 * <p>
 * Results are cached per class using {@link ClassValue}.
 * A type shared by many classes, such as a common interface or base class, is inspected only once.
 * Only classes defined by this class's loader, or by a loader that has it as an ancestor, are cached.
 * A cache entry in any other class could keep this class's loader from being reclaimed.
 * Those classes are searched on every call instead.
 *
 * @since 3.0.2
 */
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

    /**
     * Cache key.
     */
    private record Key(Method method, Class<? extends Annotation> annotationType) { }

    /**
     * Per target class cache.
     */
    private record Cache(List<Class<?>> hierarchy, Map<Key, Optional<Annotation>> found,
                         Map<Class<? extends Annotation>, Boolean> own) {
        Cache(Class<?> type) {
            this(AnnotationHierarchy.hierarchy(type).stream().filter(candidate -> candidate != Object.class).toList(),
                    new ConcurrentHashMap<>(), new ConcurrentHashMap<>());
        }
    }

    /**
     * Finds the annotation governing an invocation of the method on the target class, closest declaration first
     * (see the class documentation).
     *
     * @param method         the invoked method
     * @param targetClass    the runtime class of the invocation target, or {@code null} for the method's declaring
     *                       class (static methods)
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found anywhere in the hierarchy
     */
    public static <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationType) {
        Class<?> searchRoot = targetClass != null ? targetClass : method.getDeclaringClass();
        Cache cache = cacheFor(searchRoot);
        return annotationType.cast(cache.found().computeIfAbsent(new Key(method, annotationType), key -> Optional.ofNullable(
                searchInvocation(method, searchRoot, cache.hierarchy(), annotationType))).orElse(null));
    }

    /**
     * Returns whether the annotation is present anywhere in the hierarchy of the target class,
     * either at type level or on any declared method. This is the "should this class be intercepted at all"
     * question that every integration asks when wiring interceptors.
     *
     * @param targetClass    the class to search
     * @param annotationType the annotation to look for
     * @return {@code true} if the class or any of its methods is (directly or indirectly) annotated
     */
    public static boolean isPresent(Class<?> targetClass, Class<? extends Annotation> annotationType) {
        return cacheFor(targetClass).hierarchy().stream().anyMatch(declaring -> cacheFor(declaring).own()
                .computeIfAbsent(annotationType, type -> findDeclared(declaring, type) != null
                        || Arrays.stream(declaring.getDeclaredMethods()).anyMatch(method -> !method.isBridge()
                        && !method.isSynthetic() && findDeclared(method, type) != null)));
    }

    /**
     * Finds the annotation directly on the element or as a meta-annotation of any annotation present on it.
     *
     * @param element        the method or class to inspect
     * @param annotationType the annotation to look for
     * @param <A>            the annotation type
     * @return the annotation, or {@code null} if not found
     */
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

    /**
     * Lists the class, its interfaces, its superclass, the superclass's interfaces and so on, most specific first.
     * Each type appears once.
     */
    static List<Class<?>> hierarchy(Class<?> type) {
        return Stream.<Class<?>>iterate(type, Objects::nonNull, Class::getSuperclass)
                .flatMap(AnnotationHierarchy::withInterfaces).distinct().toList();
    }

    private static Stream<Class<?>> withInterfaces(Class<?> type) {
        return Stream.concat(Stream.of(type), Arrays.stream(type.getInterfaces()).flatMap(AnnotationHierarchy::withInterfaces));
    }

    /**
     * The methods the type declares for the invoked method's signature.
     * An exact signature match wins, otherwise every method with the same name whose parameters are wider is taken,
     * which covers generic overrides, such as {@code save(T)} implemented by {@code save(String)}.
     * When several overloads qualify, none can be ruled out, so the annotation of them applies.
     * This errs towards protecting the method, never towards leaving it unprotected.
     */
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

    /**
     * Returns the cache of a class whose cache entry cannot keep this class's loader alive.
     * Any other class gets a throwaway cache that is never stored in the {@link ClassValue}.
     */
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
