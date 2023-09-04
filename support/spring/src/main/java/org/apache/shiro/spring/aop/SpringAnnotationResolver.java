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
package org.apache.shiro.spring.aop;

import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.aop.MethodInvocation;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * {@code AnnotationResolver} implementation that uses Spring's more robust
 * {@link AnnotationUtils AnnotationUtils} to find method annotations instead of the JDKs simpler
 * (and rather lacking) {@link Method}.{@link Method#getAnnotation(Class) getAnnotation(class)}
 * implementation.
 *
 * @since 1.1
 */
public class SpringAnnotationResolver implements AnnotationResolver {

    public Annotation getAnnotation(MethodInvocation mi, Class<? extends Annotation> clazz) {
        Method m = mi.getMethod();

        Annotation a = AnnotationUtils.findAnnotation(m, clazz);
        if (a != null) {
            return a;
        }

        //The MethodInvocation's method object could be a method defined in an interface.
        //However, if the annotation existed in the interface's implementation (and not
        //the interface itself), it won't be on the above method object.  Instead, we need to
        //acquire the method representation from the targetClass and check directly on the
        //implementation itself:
        Class<?> targetClass = mi.getThis().getClass();
        m = ClassUtils.getMostSpecificMethod(m, targetClass);
        a = AnnotationUtils.findAnnotation(m, clazz);
        if (a != null) {
            return a;
        }
        // See if the class has the same annotation
        return AnnotationUtils.findAnnotation(mi.getThis().getClass(), clazz);
    }
}
