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
 * Defines an AOP-framework-independent way of determining if an Annotation exists on a Method.
 *
 * @since 1.1
 */
public interface AnnotationResolver {

    /**
     * Returns an {@link Annotation} instance of the specified type based on the given
     * {@link MethodInvocation MethodInvocation} argument, or {@code null} if no annotation
     * of that type could be found. First checks the invoked method itself and if not found,
     * then the class for the existence of the same annotation.
     *
     * @param mi    the intercepted method to be invoked.
     * @param clazz the annotation class of the annotation to find.
     * @return the method's annotation of the specified type or {@code null} if no annotation of
     * that type could be found.
     */
    Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz);
}
