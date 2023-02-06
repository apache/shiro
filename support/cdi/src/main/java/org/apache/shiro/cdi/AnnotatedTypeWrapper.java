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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.enterprise.inject.spi.AnnotatedType;
import lombok.Getter;
import lombok.experimental.Delegate;

/**
 * Wraps annotation types to facilitate additional annotations for CDI
 *
 * @param <T> type of annotated class
 */
public class AnnotatedTypeWrapper<T> implements AnnotatedType<T> {
    // the below is so the compiler doesn't complain about unchecked casts
    private abstract class AT implements AnnotatedType<T> { }
    private final @Delegate(types = AT.class) AnnotatedType<T> wrapped;
    private final @Getter Set<Annotation> annotations;


    public AnnotatedTypeWrapper(AnnotatedType<T> wrapped, Annotation... additionalAnnotations) {
        this(wrapped, true, Set.of(additionalAnnotations), Set.of());
    }


    public AnnotatedTypeWrapper(AnnotatedType<T> wrapped, boolean keepOriginalAnnotations,
            Set<Annotation> additionalAnnotations, Set<Annotation> annotationsToRemove) {
        this.wrapped = wrapped;
        Stream.Builder<Annotation> builder = Stream.builder();
        if (keepOriginalAnnotations) {
            var annotationTypesToExclude = annotationsToRemove.stream()
                    .map(AnnotatedTypeWrapper::checkIfAnnotation)
                    .map(Annotation::annotationType).collect(Collectors.toSet());
            wrapped.getAnnotations().stream().filter(ann ->
                    !annotationTypesToExclude.contains(ann.annotationType()))
                    .forEach(builder::add);
        }
        additionalAnnotations.forEach(annotation -> addToBuilder(builder, annotation));
        annotations = builder.build().collect(Collectors.toSet());
    }

    @Override
    public boolean isAnnotationPresent(Class<? extends Annotation> annotationType) {
        return annotations.stream().anyMatch(annotation -> annotationType.isInstance(annotation));
    }

    private void addToBuilder(Stream.Builder<Annotation> builder, Annotation ann) {
        checkIfAnnotation(ann);
        builder.add(ann);
    }

    private static Annotation checkIfAnnotation(Annotation ann) {
        if (!ann.annotationType().isInstance(ann)) {
            throw new IllegalArgumentException(ann.getClass().getName());
        }
        return ann;
    }
}
