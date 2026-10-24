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
package org.apache.shiro.guice.aop;

import com.google.inject.AbstractModule;
import com.google.inject.matcher.Matcher;
import org.apache.shiro.aop.AnnotationHierarchy;
import org.apache.shiro.aop.AnnotationMethodInterceptor;
import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.authz.aop.AuthorizationAnnotations;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Install this module to enable Shiro AOP functionality in Guice.  You may extend it to add your own Shiro
 * interceptors, override the default ones, or provide a specific {@link org.apache.shiro.aop.AnnotationResolver}.
 * <p>
 * Annotations are honored on the class, its superclasses, its interfaces, overridden and interface methods and
 * as meta-annotations, exactly as in the other Shiro integrations: a class is enhanced when an annotation is
 * present anywhere in its hierarchy, and each invocation is then checked by the interceptor's
 * {@link AnnotationMethodInterceptor#supports(org.apache.shiro.aop.MethodInvocation) resolver}.
 */
public class ShiroAopModule extends AbstractModule {
    /**
     * Every method Guice can enhance; whether a given invocation is actually subject to an annotation is
     * decided by the interceptor through the shared annotation resolver.
     */
    private static final Matcher<Method> ENHANCEABLE_METHODS = method -> !Modifier.isStatic(method.getModifiers())
            && !method.isSynthetic() && !method.isBridge() && method.getDeclaringClass() != Object.class;

    @Override
    protected final void configure() {
        AnnotationResolver resolver = createAnnotationResolver();
        configureDefaultInterceptors(resolver);
        configureInterceptors(resolver);
    }

    protected final void bindShiroInterceptor(final AnnotationMethodInterceptor methodInterceptor) {
        Class<? extends Annotation> annotation = methodInterceptor.getHandler().getAnnotationClass();
        Matcher<Class<?>> securedClasses = type -> AnnotationHierarchy.isPresent(type, annotation);
        bindInterceptor(securedClasses, ENHANCEABLE_METHODS, new AopAllianceMethodInterceptorAdapter(methodInterceptor));
    }

    protected AnnotationResolver createAnnotationResolver() {
        return new DefaultAnnotationResolver();
    }

    protected void configureDefaultInterceptors(AnnotationResolver resolver) {
        AuthorizationAnnotations.createMethodInterceptors(resolver, AuthorizationAnnotations.shiroTypes())
                .forEach(this::bindShiroInterceptor);
    }

    protected void configureInterceptors(AnnotationResolver resolver) {

    }
}
