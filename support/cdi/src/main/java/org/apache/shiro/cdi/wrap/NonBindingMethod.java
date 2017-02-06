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

import org.apache.shiro.cdi.literal.NonbindingLiteral;

import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedParameter;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.util.AnnotationLiteral;
import javax.enterprise.util.Nonbinding;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class NonBindingMethod<T extends Annotation> implements AnnotatedMethod<T> {
    private static final AnnotationLiteral<Nonbinding> NONBINDING_ANNOTATION_LITERAL = new NonbindingLiteral();

    private final AnnotatedMethod<T> delegate;
    private final Set<Annotation> annotations;

    NonBindingMethod(final AnnotatedMethod<T> m) {
        delegate = m;
        annotations = new HashSet<Annotation>(m.getAnnotations().size() + 1);
        this.annotations.addAll(delegate.getAnnotations());
        this.annotations.add(NONBINDING_ANNOTATION_LITERAL);
    }

    @Override
    public Method getJavaMember() {
        return delegate.getJavaMember();
    }

    @Override
    public List<AnnotatedParameter<T>> getParameters() {
        return delegate.getParameters();
    }

    @Override
    public boolean isStatic() {
        return delegate.isStatic();
    }

    @Override
    public AnnotatedType<T> getDeclaringType() {
        return delegate.getDeclaringType();
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
        return annotationType == Nonbinding.class ? annotationType.cast(NONBINDING_ANNOTATION_LITERAL) : delegate.getAnnotation(annotationType);
    }

    @Override
    public Set<Annotation> getAnnotations() {
        return annotations;
    }

    @Override
    public boolean isAnnotationPresent(final Class<? extends Annotation> annotationType) {
        return Nonbinding.class == annotationType || delegate.isAnnotationPresent(annotationType);
    }
}
