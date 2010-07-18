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

/**
 * Default {@code AnnotationResolver} implementation that merely inspects the
 * {@link MethodInvocation MethodInvocation}'s {@link MethodInvocation#getMethod() target method},
 * and returns {@code targetMethod}.{@link Method#getAnnotation(Class) getAnnotation(class)}.
 * <p/>
 * Unfortunately Java's default reflection API for Annotations is not very robust, and this logic
 * may not be enough - if the incoming method invocation represents a method from an interface,
 * this default logic would not discover the annotation if it existed on the method implementation
 * directly (as opposed to being defined directly in the interface definition).
 * <p/>
 * More complex class hierarchy traversal logic is required to exhaust a method's target object's
 * classes, parent classes, interfaces and parent interfaces.  That logic will likely be added
 * to this implementation in due time, but for now, this implementation relies on the JDK's default
 * {@link Method#getAnnotation(Class) Method.getAnnotation(class)} logic.
 *
 * @since 1.1
 */
public class DefaultAnnotationResolver implements AnnotationResolver {

    /**
     * Returns {@code methodInvocation.}{@link org.apache.shiro.aop.MethodInvocation#getMethod() getMethod()}.{@link Method#getAnnotation(Class) getAnnotation(clazz)}.
     *
     * @param mi    the intercepted method to be invoked.
     * @param clazz the annotation class to use to find an annotation instance on the method.
     * @return the discovered annotation or {@code null} if an annotation instance could not be
     *         found.
     */
    public Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz) {
        if (mi == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }
        Method m = mi.getMethod();
        if (m == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);

        }
        return m.getAnnotation(clazz);
    }
}
