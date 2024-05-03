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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


public class ShiroAopModuleTest {

    private Map<Class<? extends Annotation>, Method> protectedMethods;
    private Map<Class<? extends Annotation>, Class<? extends AnnotationMethodInterceptor>> interceptorTypes;

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
                assertSame(annotationResolver, resolver);
                bind(Object.class).annotatedWith(Names.named("configureDefaultInterceptors"));
            }

            @Override
            protected void configureInterceptors(AnnotationResolver resolver) {
                assertSame(annotationResolver, resolver);
                bind(Object.class).annotatedWith(Names.named("configureInterceptors"));
            }
        };

        boolean calledDefault = false;
        boolean calledCustom = false;

        for (Element e : Elements.getElements(underTest)) {
            if (e instanceof Binding) {
                Key key = ((Binding) e).getKey();
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
    }

    @Test
    void testBindShiroInterceptor() {


        ShiroAopModule underTest = new ShiroAopModule() {
            @Override
            protected void configureInterceptors(AnnotationResolver resolver) {
                bindShiroInterceptor(new MyAnnotationMethodInterceptor());
            }
        };

        List<Element> elements = Elements.getElements(underTest);

        for (Element element : elements) {
            if (element instanceof InterceptorBinding) {
                InterceptorBinding binding = (InterceptorBinding) element;
                assertTrue(binding.getClassMatcher().matches(getClass()));
                Method method = null;
                Class<? extends Annotation> theAnnotation = null;

                for (Class<? extends Annotation> annotation : protectedMethods.keySet()) {
                    if (binding.getMethodMatcher().matches(protectedMethods.get(annotation))) {
                        method = protectedMethods.get(annotation);
                        theAnnotation = annotation;
                        protectedMethods.remove(annotation);
                        break;
                    }
                }

                if (method == null) {
                    fail("Did not expect interceptor binding " + binding.getInterceptors());
                }

                List<MethodInterceptor> interceptors = binding.getInterceptors();
                assertEquals(1, interceptors.size());
                assertTrue(interceptors.get(0) instanceof AopAllianceMethodInterceptorAdapter);
                assertTrue(interceptorTypes.get(theAnnotation)
                                .isInstance(((AopAllianceMethodInterceptorAdapter) interceptors.get(0)).shiroInterceptor));

            }
        }

        assertTrue(protectedMethods.isEmpty(), "Not all interceptors were bound.");
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
