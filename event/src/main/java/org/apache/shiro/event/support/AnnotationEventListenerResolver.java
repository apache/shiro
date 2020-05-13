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
package org.apache.shiro.event.support;

import org.apache.shiro.event.Subscribe;
import org.apache.shiro.lang.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Inspects an object for annotated methods of interest and creates an {@link EventListener} instance for each method
 * discovered.  An event bus will call the resulting listeners as relevant events arrive.
 * <p/>
 * The default {@link #setAnnotationClass(Class) annotationClass} is {@link Subscribe}, indicating each
 * {@link Subscribe}-annotated method will be represented as an EventListener.
 *
 * @see SingleArgumentMethodEventListener
 * @since 1.3
 */
public class AnnotationEventListenerResolver implements EventListenerResolver {

    private Class<? extends Annotation> annotationClass;

    public AnnotationEventListenerResolver() {
        this.annotationClass = Subscribe.class;
    }

    /**
     * Returns a new collection of {@link EventListener} instances, each instance corresponding to an annotated
     * method discovered on the specified {@code instance} argument.
     *
     * @param instance the instance to inspect for annotated event handler methods.
     * @return a new collection of {@link EventListener} instances, each instance corresponding to an annotated
     *         method discovered on the specified {@code instance} argument.
     */
    public List<EventListener> getEventListeners(Object instance) {
        if (instance == null) {
            return Collections.emptyList();
        }

        List<Method> methods = ClassUtils.getAnnotatedMethods(instance.getClass(), getAnnotationClass());
        if (methods == null || methods.isEmpty()) {
            return Collections.emptyList();
        }

        List<EventListener> listeners = new ArrayList<EventListener>(methods.size());

        for (Method m : methods) {
            listeners.add(new SingleArgumentMethodEventListener(instance, m));
        }

        return listeners;
    }

    /**
     * Returns the type of annotation that indicates a method that should be represented as an {@link EventListener},
     * defaults to {@link Subscribe}.
     *
     * @return the type of annotation that indicates a method that should be represented as an {@link EventListener},
     *         defaults to {@link Subscribe}.
     */
    public Class<? extends Annotation> getAnnotationClass() {
        return annotationClass;
    }

    /**
     * Sets the type of annotation that indicates a method that should be represented as an {@link EventListener}.
     * The default value is {@link Subscribe}.
     *
     * @param annotationClass the type of annotation that indicates a method that should be represented as an
     *                        {@link EventListener}.  The default value is {@link Subscribe}.
     */
    public void setAnnotationClass(Class<? extends Annotation> annotationClass) {
        this.annotationClass = annotationClass;
    }
}
