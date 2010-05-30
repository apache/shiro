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
package org.apache.shiro.authz.aop;

import java.lang.annotation.Annotation;

import org.apache.shiro.aop.AnnotationHandler;
import org.apache.shiro.authz.AuthorizationException;

/**
 * An AnnotationHandler that executes authorization (access control) behavior based on directive(s) found in a
 * JSR-175 Annotation.
 *
 * @since 0.9.0
 */
public abstract class AuthorizingAnnotationHandler extends AnnotationHandler {

    /**
     * Constructs an <code>AuthorizingAnnotationHandler</code> who processes annotations of the
     * specified type.  Immediately calls <code>super(annotationClass)</code>.
     *
     * @param annotationClass the type of annotation this handler will process.
     */
    public AuthorizingAnnotationHandler(Class<? extends Annotation> annotationClass) {
        super(annotationClass);
    }

    /**
     * Ensures the calling Subject is authorized to execute based on the directive(s) found in the given
     * annotation.
     * <p/>
     * As this is an AnnotationMethodInterceptor, the implementations of this method typically inspect the annotation
     * and perform a corresponding authorization check based.
     *
     * @param a the <code>Annotation</code> to check for performing an authorization check.
     * @throws org.apache.shiro.authz.AuthorizationException if the class/instance/method is not allowed to proceed/execute.
     */
    public abstract void assertAuthorized(Annotation a) throws AuthorizationException;
}
