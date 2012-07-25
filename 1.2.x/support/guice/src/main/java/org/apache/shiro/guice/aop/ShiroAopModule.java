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
import com.google.inject.matcher.AbstractMatcher;
import com.google.inject.matcher.Matchers;
import org.apache.shiro.aop.AnnotationMethodInterceptor;
import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.authz.aop.*;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * Install this module to enable Shiro AOP functionality in Guice.  You may extend it to add your own Shiro
 * interceptors, override the default ones, or provide a specific {@link org.apache.shiro.aop.AnnotationResolver}.
 */
public class ShiroAopModule extends AbstractModule {
    @Override
    protected final void configure() {
        AnnotationResolver resolver = createAnnotationResolver();
        configureDefaultInterceptors(resolver);
        configureInterceptors(resolver);
    }

    protected final void bindShiroInterceptor(final AnnotationMethodInterceptor methodInterceptor) {
        bindInterceptor(Matchers.any(), new AbstractMatcher<Method>() {
            public boolean matches(Method method) {
                Class<? extends Annotation> annotation = methodInterceptor.getHandler().getAnnotationClass();
                return method.getAnnotation(annotation) != null
                        || method.getDeclaringClass().getAnnotation(annotation) != null;
            }
        }, new AopAllianceMethodInterceptorAdapter(methodInterceptor));
    }

    protected AnnotationResolver createAnnotationResolver() {
        return new DefaultAnnotationResolver();
    }

    protected void configureDefaultInterceptors(AnnotationResolver resolver) {
        bindShiroInterceptor(new RoleAnnotationMethodInterceptor(resolver));
        bindShiroInterceptor(new PermissionAnnotationMethodInterceptor(resolver));
        bindShiroInterceptor(new AuthenticatedAnnotationMethodInterceptor(resolver));
        bindShiroInterceptor(new UserAnnotationMethodInterceptor(resolver));
        bindShiroInterceptor(new GuestAnnotationMethodInterceptor(resolver));
    }

    protected void configureInterceptors(AnnotationResolver resolver) {

    }
}
