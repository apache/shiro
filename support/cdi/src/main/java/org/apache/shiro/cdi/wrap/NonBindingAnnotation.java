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
package org.apache.shiro.cdi.wrap;

import org.apache.shiro.cdi.literal.InterceptorBindingLiteral;

import javax.enterprise.inject.spi.AnnotatedConstructor;
import javax.enterprise.inject.spi.AnnotatedField;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.util.AnnotationLiteral;
import javax.interceptor.InterceptorBinding;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

public class NonBindingAnnotation<T extends Annotation> implements AnnotatedType<T> {
    private static final AnnotationLiteral<InterceptorBinding> INTERCEPTOR_BINDING_ANNOTATION_LITERAL = new InterceptorBindingLiteral();

    private final AnnotatedType<T> delegate;
    private final Set<AnnotatedMethod<? super T>> methods;
    private final Set<Annotation> annotations;

    public NonBindingAnnotation(final AnnotatedType<T> annotatedType) {
        this.delegate = annotatedType;
        this.methods = new HashSet<AnnotatedMethod<? super T>>();
        for (final AnnotatedMethod<? super T> m : delegate.getMethods()) {
            this.methods.add(new NonBindingMethod<T>((AnnotatedMethod<T>) m));
        }

        this.annotations = new HashSet<Annotation>(delegate.getAnnotations().size() + 1);
        this.annotations.addAll(delegate.getAnnotations());
        this.annotations.add(INTERCEPTOR_BINDING_ANNOTATION_LITERAL);
    }

    @Override
    public Class<T> getJavaClass() {
        return delegate.getJavaClass();
    }

    @Override
    public Set<AnnotatedConstructor<T>> getConstructors() {
        return delegate.getConstructors();
    }

    @Override
    public Set<AnnotatedMethod<? super T>> getMethods() {
        return methods;
    }

    @Override
    public Set<AnnotatedField<? super T>> getFields() {
        return delegate.getFields();
    }

    @Override
    public Type getBaseType() {
        return delegate.getBaseType();
    }

    @Override
    public Set<Type> getTypeClosure() {
        return delegate.getTypeClosure();
    }

    @Override
    public <T extends Annotation> T getAnnotation(final Class<T> annotationType) {
        return annotationType == InterceptorBinding.class ? annotationType.cast(INTERCEPTOR_BINDING_ANNOTATION_LITERAL) : delegate.getAnnotation(annotationType);
    }

    @Override
    public Set<Annotation> getAnnotations() {
        return annotations;
    }

    @Override
    public boolean isAnnotationPresent(final Class<? extends Annotation> annotationType) {
        return annotationType == InterceptorBinding.class || delegate.isAnnotationPresent(annotationType);
    }
}
