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

/**
 * MethodInterceptor that inspects a specific annotation on the method invocation before continuing
 * its execution.
 * </p>
 * The annotation is acquired from the {@link MethodInvocation MethodInvocation} via a
 * {@link AnnotationResolver AnnotationResolver} instance that may be configured.  Unless
 * overridden, the default {@code AnnotationResolver} is a
 *
 * @since 0.9
 */
public abstract class AnnotationMethodInterceptor extends MethodInterceptorSupport {

    private AnnotationHandler handler;

    /**
     * The resolver to use to find annotations on intercepted methods.
     *
     * @since 1.1
     */
    private AnnotationResolver resolver;

    /**
     * Constructs an <code>AnnotationMethodInterceptor</code> with the
     * {@link AnnotationHandler AnnotationHandler} that will be used to process annotations of a
     * corresponding type.
     *
     * @param handler the handler to delegate to for processing the annotation.
     */
    public AnnotationMethodInterceptor(AnnotationHandler handler) {
        this(handler, new DefaultAnnotationResolver());
    }

    /**
     * Constructs an <code>AnnotationMethodInterceptor</code> with the
     * {@link AnnotationHandler AnnotationHandler} that will be used to process annotations of a
     * corresponding type, using the specified {@code AnnotationResolver} to acquire annotations
     * at runtime.
     *
     * @param handler  the handler to use to process any discovered annotation
     * @param resolver the resolver to use to locate/acquire the annotation
     * @since 1.1
     */
    public AnnotationMethodInterceptor(AnnotationHandler handler, AnnotationResolver resolver) {
        if (handler == null) {
            throw new IllegalArgumentException("AnnotationHandler argument cannot be null.");
        }
        setHandler(handler);
        setResolver(resolver != null ? resolver : new DefaultAnnotationResolver());
    }

    /**
     * Returns the {@code AnnotationHandler} used to perform authorization behavior based on
     * an annotation discovered at runtime.
     *
     * @return the {@code AnnotationHandler} used to perform authorization behavior based on
     *         an annotation discovered at runtime.
     */
    public AnnotationHandler getHandler() {
        return handler;
    }

    /**
     * Sets the {@code AnnotationHandler} used to perform authorization behavior based on
     * an annotation discovered at runtime.
     *
     * @param handler the {@code AnnotationHandler} used to perform authorization behavior based on
     *                an annotation discovered at runtime.
     */
    public void setHandler(AnnotationHandler handler) {
        this.handler = handler;
    }

    /**
     * Returns the {@code AnnotationResolver} to use to acquire annotations from intercepted
     * methods at runtime.  The annotation is then used by the {@link #getHandler handler} to
     * perform authorization logic.
     *
     * @return the {@code AnnotationResolver} to use to acquire annotations from intercepted
     *         methods at runtime.
     * @since 1.1
     */
    public AnnotationResolver getResolver() {
        return resolver;
    }

    /**
     * Returns the {@code AnnotationResolver} to use to acquire annotations from intercepted
     * methods at runtime.  The annotation is then used by the {@link #getHandler handler} to
     * perform authorization logic.
     *
     * @param resolver the {@code AnnotationResolver} to use to acquire annotations from intercepted
     *                 methods at runtime.
     * @since 1.1
     */
    public void setResolver(AnnotationResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Returns <code>true</code> if this interceptor supports, that is, should inspect, the specified
     * <code>MethodInvocation</code>, <code>false</code> otherwise.
     * <p/>
     * The default implementation simply does the following:
     * <p/>
     * <code>return {@link #getAnnotation(MethodInvocation) getAnnotation(mi)} != null</code>
     *
     * @param mi the <code>MethodInvocation</code> for the method being invoked.
     * @return <code>true</code> if this interceptor supports, that is, should inspect, the specified
     *         <code>MethodInvocation</code>, <code>false</code> otherwise.
     */
    public boolean supports(MethodInvocation mi) {
        return getAnnotation(mi) != null;
    }

    /**
     * Returns the Annotation that this interceptor will process for the specified method invocation.
     * <p/>
     * The default implementation acquires the annotation using an annotation
     * {@link #getResolver resolver} using the internal annotation {@link #getHandler handler}'s
     * {@link org.apache.shiro.aop.AnnotationHandler#getAnnotationClass() annotationClass}.
     *
     * @param mi the MethodInvocation wrapping the Method from which the Annotation will be acquired.
     * @return the Annotation that this interceptor will process for the specified method invocation.
     */
    protected Annotation getAnnotation(MethodInvocation mi) {
        return getResolver().getAnnotation(mi, getHandler().getAnnotationClass());
    }
}
