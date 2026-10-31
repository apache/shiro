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
package org.apache.shiro.web.jaxrs;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Configuration;
import jakarta.ws.rs.core.FeatureContext;
import org.apache.shiro.aop.fixtures.ComposedAnnotated;
import org.apache.shiro.aop.fixtures.MethodSecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.SecuredInterfaceImpl;
import org.apache.shiro.aop.fixtures.SecuredSubclass;
import org.apache.shiro.aop.fixtures.Unsecured;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ShiroAnnotationFilterFeatureTest {

    static class Jsr250Resource {
        @RolesAllowed("admin")
        public String admin() {
            return "admin";
        }
    }

    /** An annotation from some third-party library that is not related to Shiro. */
    @Retention(RetentionPolicy.RUNTIME)
    @interface ForeignAnnotation {
        Class<?> handler() default Object.class;
    }

    @ForeignAnnotation(handler = Runnable.class)
    interface ForeignInterface {
    }

    static class ForeignResource implements ForeignInterface {
        @ForeignAnnotation
        public String foreign() {
            return "foreign";
        }
    }

    private static FeatureContext configure(Class<?> resourceClass, String methodName, boolean jsr250)
            throws NoSuchMethodException {
        Method method = resourceClass.getMethod(methodName);
        ResourceInfo resourceInfo = mock(ResourceInfo.class);
        when(resourceInfo.getResourceMethod()).thenReturn(method);
        when(resourceInfo.getResourceClass()).thenAnswer(invocation -> resourceClass);
        Configuration configuration = mock(Configuration.class);
        when(configuration.getProperty(SubjectPrincipalRequestFilter.SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM))
                .thenReturn(jsr250);
        FeatureContext context = mock(FeatureContext.class);
        when(context.getConfiguration()).thenReturn(configuration);
        new ShiroAnnotationFilterFeature().configure(resourceInfo, context);
        return context;
    }

    private static AnnotationAuthorizationFilter registeredFilter(FeatureContext context) {
        ArgumentCaptor<AnnotationAuthorizationFilter> captor = ArgumentCaptor.forClass(AnnotationAuthorizationFilter.class);
        verify(context).register(captor.capture(), eq(Priorities.AUTHORIZATION));
        return captor.getValue();
    }

    @Test
    void interfaceTypeLevelAnnotation() throws NoSuchMethodException {
        assertThat(registeredFilter(configure(SecuredInterfaceImpl.class, "adminOnly", false))).isNotNull();
    }

    @Test
    void interfaceMethodLevelAnnotation() throws NoSuchMethodException {
        assertThat(registeredFilter(configure(MethodSecuredInterfaceImpl.class, "read", false))).isNotNull();
        verify(configure(MethodSecuredInterfaceImpl.class, "open", false), never()).register(any(), anyInt());
    }

    @Test
    void superclassAndComposedAnnotations() throws NoSuchMethodException {
        assertThat(registeredFilter(configure(SecuredSubclass.class, "subclassOperation", false))).isNotNull();
        assertThat(registeredFilter(configure(ComposedAnnotated.class, "composed", false))).isNotNull();
    }

    @Test
    void jsr250OnlyWhenPrincipalParamDisabled() throws NoSuchMethodException {
        verify(configure(Jsr250Resource.class, "admin", false), never()).register(any(), anyInt());
        assertThat(registeredFilter(configure(Jsr250Resource.class, "admin", true))).isNotNull();
    }

    @Test
    void unsecuredResource() throws NoSuchMethodException {
        verify(configure(Unsecured.class, "open", true), never()).register(any(), anyInt());
    }

    @Test
    void foreignAnnotationsAreIgnored() throws NoSuchMethodException {
        verify(configure(ForeignResource.class, "foreign", true), never()).register(any(), anyInt());
    }

    @Test
    void onlyRegisteredAnnotationsGetAHandler() throws NoSuchMethodException {
        Annotation foreign = ForeignResource.class.getMethod("foreign").getAnnotation(ForeignAnnotation.class);
        assertThatThrownBy(() -> new AnnotationAuthorizationFilter(List.of(foreign)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
