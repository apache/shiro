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
 * MethodInterceptor that inspects a specific annotation on the method invocation before continuing
 * its execution.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AnnotationMethodInterceptor extends MethodInterceptorSupport {

    private AnnotationHandler handler;

    /**
     * Constructs an <code>AnnotationMethodInterceptor</code> with the
     * {@link AnnotationHandler AnnotationHandler} that will be used to process annotations of a corresponding
     * type.
     *
     * @param handler the handler to delegate to for processing the annotation.
     */
    public AnnotationMethodInterceptor(AnnotationHandler handler) {
        setHandler(handler);
    }

    public AnnotationHandler getHandler() {
        return handler;
    }

    public void setHandler(AnnotationHandler handler) {
        this.handler = handler;
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
     * The default implementation merely gets the underlying {@link Method Method} from the supplied
     * <code>MethodInvocation</code> argument, and returns:
     * <p/>
     * <code>mi.{@link Method#getAnnotation(Class) getAnnotation}({@link org.apache.shiro.aop.AnnotationHandler#getAnnotationClass() handler.getAnnotationClass()});</code>
     *
     * @param mi the MethodInvocation wrapping the Method from which the Annotation will be acquired.
     * @return the Annotation that this interceptor will process for the specified method invocation.
     * @throws IllegalArgumentException if the supplied <code>MethodInvocation</code> argument is <code>null</code> or
     *                                  its underlying <code>Method</code> is <code>null</code>.
     */
    protected Annotation getAnnotation(MethodInvocation mi) throws IllegalArgumentException {
        if (mi == null) {
            throw new IllegalArgumentException("method argument cannot be null");
        }
        Method m = mi.getMethod();
        if (m == null) {
            String msg = MethodInvocation.class.getName() + " parameter incorrectly constructed.  getMethod() returned null";
            throw new IllegalArgumentException(msg);

        }
        return m.getAnnotation(getHandler().getAnnotationClass());
    }

}
