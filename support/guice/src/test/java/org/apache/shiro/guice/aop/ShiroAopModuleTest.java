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

import com.google.inject.Binding;
import com.google.inject.Key;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import com.google.inject.spi.Element;
import com.google.inject.spi.Elements;
import com.google.inject.spi.InterceptorBinding;
import org.aopalliance.intercept.MethodInterceptor;
import org.apache.shiro.aop.AnnotationHandler;
import org.apache.shiro.aop.AnnotationMethodInterceptor;
import org.apache.shiro.aop.AnnotationResolver;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthenticatedAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.GuestAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.PermissionAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.RoleAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.UserAnnotationMethodInterceptor;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;
import org.apache.shiro.config.ConfigurationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.fail;



public class ShiroAopModuleTest {

    @RequiresRoles({})
    public interface EmptyRoles {
    }

    public static class EmptyRolesService implements EmptyRoles {
        public void operation() {
        }
    }

    public static class EmptyPermissionsBase {
        @RequiresPermissions({})
        public void operation() {
        }
    }

    public static class EmptyPermissionsService extends EmptyPermissionsBase {
        @Override
        public void operation() {
        }
    }

    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    @RequiresRoles({})
    public @interface EmptyComposedRoles {
    }

    @EmptyComposedRoles
    public static class EmptyComposedRolesService {
        public void operation() {
        }
    }

    private Map<Class<? extends Annotation>, Method> protectedMethods;
    private Map<Class<? extends Annotation>, Class<? extends AnnotationMethodInterceptor>> interceptorTypes;

    @Test
    @ResourceLock("AuthorizationConfigPolicy.strictParsing")
    void validatesHierarchyWhenMatchingSecuredClasses() {
        boolean strictParsing = AuthorizationConfigPolicy.isStrictParsing();
        try {
            var bindings = Elements.getElements(new ShiroAopModule()).stream()
                    .filter(InterceptorBinding.class::isInstance).map(InterceptorBinding.class::cast).toList();
            for (Class<?> type : List.of(EmptyRolesService.class, EmptyPermissionsService.class,
                    EmptyComposedRolesService.class)) {
                AuthorizationConfigPolicy.setStrictParsing(false);
                var matchingBindings = bindings.stream().filter(binding -> binding.getClassMatcher().matches(type)).toList();
                assertThat(matchingBindings).isNotEmpty();
                AuthorizationConfigPolicy.setStrictParsing(true);
                matchingBindings.forEach(binding -> assertThatExceptionOfType(ConfigurationException.class)
                        .isThrownBy(() -> binding.getClassMatcher().matches(type)));
            }
        } finally {
            AuthorizationConfigPolicy.setStrictParsing(strictParsing);
        }
    }

    @Test
    void testGetAnnotationResolver() {

        final AnnotationResolver annotationResolver = new DefaultAnnotationResolver();

        ShiroAopModule underTest = new ShiroAopModule() {

            @Override
            protected AnnotationResolver createAnnotationResolver() {
                return annotationResolver;
            }

            @Override
            protected void configureDefaultInterceptors(AnnotationResolver resolver) {
                assertThat(resolver).isSameAs(annotationResolver);
                bind(Object.class).annotatedWith(Names.named("configureDefaultInterceptors"));
            }

            @Override
            protected void configureInterceptors(AnnotationResolver resolver) {
                assertThat(resolver).isSameAs(annotationResolver);
                bind(Object.class).annotatedWith(Names.named("configureInterceptors"));
            }
        };

        boolean calledDefault = false;
        boolean calledCustom = false;

        for (Element e : Elements.getElements(underTest)) {
            if (e instanceof Binding<?> binding) {
                Key<?> key = binding.getKey();
                if (Named.class.isAssignableFrom(key.getAnnotation().annotationType())
                        && "configureInterceptors".equals(((Named) key.getAnnotation()).value())
                        && key.getTypeLiteral().getRawType().equals(Object.class)) {
                    calledCustom = true;
                }
                if (Named.class.isAssignableFrom(key.getAnnotation().annotationType())
                        && "configureDefaultInterceptors".equals(((Named) key.getAnnotation()).value())
                        && key.getTypeLiteral().getRawType().equals(Object.class)) {
                    calledDefault = true;
                }
            }
        }
        assertThat(calledDefault).isTrue();
        assertThat(calledCustom).isTrue();
    }

    @Test
    void testBindShiroInterceptor() throws NoSuchMethodException {


        ShiroAopModule underTest = new ShiroAopModule() {
            @Override
            protected void configureInterceptors(AnnotationResolver resolver) {
                bindShiroInterceptor(new MyAnnotationMethodInterceptor());
            }
        };

        List<Element> elements = Elements.getElements(underTest);

        for (Element element : elements) {
            if (element instanceof InterceptorBinding binding) {
                List<MethodInterceptor> interceptors = binding.getInterceptors();
                assertThat(interceptors).hasSize(1);
                assertThat(interceptors.get(0)).isInstanceOf(AopAllianceMethodInterceptorAdapter.class);
                AnnotationMethodInterceptor shiroInterceptor = (AnnotationMethodInterceptor)
                        ((AopAllianceMethodInterceptorAdapter) interceptors.get(0)).shiroInterceptor;
                Class<? extends Annotation> theAnnotation = shiroInterceptor.getHandler().getAnnotationClass();
                Method method = protectedMethods.remove(theAnnotation);
                if (method == null) {
                    fail("Did not expect interceptor binding " + binding.getInterceptors());
                }
                assertThat(interceptorTypes.get(theAnnotation).isInstance(shiroInterceptor)).isTrue();

                // the class matcher gates on the annotation being present anywhere in the class hierarchy
                assertThat(binding.getClassMatcher().matches(getClass())).isTrue();
                assertThat(binding.getClassMatcher().matches(Object.class)).isFalse();
                // every enhanceable method of a matched class is bound; the interceptor decides per invocation
                assertThat(binding.getMethodMatcher().matches(method)).isTrue();
                assertThat(binding.getMethodMatcher().matches(getClass().getMethod("setup"))).isTrue();
            }
        }

        assertThat(protectedMethods.isEmpty()).as("Not all interceptors were bound.").isTrue();
    }

    @Target({ElementType.TYPE, ElementType.METHOD})
    @Retention(RetentionPolicy.RUNTIME)
    private @interface MyTestAnnotation {
    }

    private static class MyAnnotationHandler extends AnnotationHandler {

        /**
         * Constructs an <code>AnnotationHandler</code> who processes annotations of the
         * specified type.  Immediately calls {@link #setAnnotationClass(Class)}.
         *
         * @param annotationClass the type of annotation this handler will process.
         */
        MyAnnotationHandler(Class<? extends Annotation> annotationClass) {
            super(annotationClass);
        }
    }

    private static class MyAnnotationMethodInterceptor extends AnnotationMethodInterceptor {
        MyAnnotationMethodInterceptor() {
            super(new MyAnnotationHandler(MyTestAnnotation.class));
        }

        @Override
        public Object invoke(MethodInvocation methodInvocation) throws Throwable {
            return null;
        }
    }


    @RequiresRoles("role")
    public void roleProtected() {

    }

    @RequiresPermissions("permission")
    public void permissionProtected() {

    }

    @RequiresAuthentication
    public void authProtected() {

    }

    @RequiresUser
    public void userProtected() {

    }

    @RequiresGuest
    public void guestProtected() {

    }

    @ShiroAopModuleTest.MyTestAnnotation
    public void myTestProtected() {

    }

    @BeforeEach
    public void setup() throws NoSuchMethodException {
        protectedMethods = new HashMap<Class<? extends Annotation>, Method>();
        protectedMethods.put(RequiresRoles.class, getClass().getMethod("roleProtected"));
        protectedMethods.put(RequiresPermissions.class, getClass().getMethod("permissionProtected"));
        protectedMethods.put(RequiresAuthentication.class, getClass().getMethod("authProtected"));
        protectedMethods.put(RequiresUser.class, getClass().getMethod("userProtected"));
        protectedMethods.put(RequiresGuest.class, getClass().getMethod("guestProtected"));
        protectedMethods.put(MyTestAnnotation.class, getClass().getMethod("myTestProtected"));

        interceptorTypes = new HashMap<Class<? extends Annotation>, Class<? extends AnnotationMethodInterceptor>>();
        interceptorTypes.put(RequiresRoles.class, RoleAnnotationMethodInterceptor.class);
        interceptorTypes.put(RequiresPermissions.class, PermissionAnnotationMethodInterceptor.class);
        interceptorTypes.put(RequiresAuthentication.class, AuthenticatedAnnotationMethodInterceptor.class);
        interceptorTypes.put(RequiresUser.class, UserAnnotationMethodInterceptor.class);
        interceptorTypes.put(RequiresGuest.class, GuestAnnotationMethodInterceptor.class);
        interceptorTypes.put(MyTestAnnotation.class, MyAnnotationMethodInterceptor.class);
    }
}
