/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.cdi;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ejb.Stateless;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.spi.AnnotatedType;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Annotated Type Wrapper tests
 */
@ExtendWith(MockitoExtension.class)
class AnnotatedTypeWrapperTest {
    @Mock
    private AnnotatedType<Void> annotatedType;

    @RequiresAuthentication
    @RequiresGuest
    @RequiresPermissions("hello")
    private final class Annotated {
    }

    @ShiroSecureAnnotation
    private final class ShiroSecureAnnotated {
    }

    @Stateless
    private final class StatelessAnnotated {
    }

    @SessionScoped
    @SuppressWarnings("serial")
    private static final class SessionScopedAnnotated implements Serializable {
    }

    @Test
    void noAnnotations() {
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType);
        assertEquals(0, wrapper.getAnnotations().size());
    }

    @Test
    void noAdditionalAnnotations() {
        initializeStubs();
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType);
        assertEquals(3, wrapper.getAnnotations().size());
    }

    @Test
    @SuppressWarnings("MagicNumber")
    void twoAdditionalAnnotations() {
        initializeStubs();
        Annotation shiroSecureAnnotation = getAnnotation(ShiroSecureAnnotated.class, ShiroSecureAnnotation.class);
        Annotation statelessAnnotation = getAnnotation(StatelessAnnotated.class, Stateless.class);
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, shiroSecureAnnotation, statelessAnnotation);
        assertEquals(5, wrapper.getAnnotations().size());
        assertTrue(wrapper.isAnnotationPresent(ShiroSecureAnnotation.class));
        assertTrue(wrapper.isAnnotationPresent(Stateless.class));
        assertTrue(wrapper.isAnnotationPresent(RequiresAuthentication.class));
        assertTrue(wrapper.isAnnotationPresent(RequiresGuest.class));
        assertTrue(wrapper.isAnnotationPresent(RequiresPermissions.class));
    }

    @Test
    void removeAnnotations() {
        initializeStubs();
        Set<Annotation> sessionScopeAnnoationsSet = Set.of(getAnnotation(SessionScopedAnnotated.class, SessionScoped.class));
        Set<Annotation> requiresGuestAnnoationsSet = Set.of(getAnnotation(Annotated.class, RequiresGuest.class));
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, true, sessionScopeAnnoationsSet, requiresGuestAnnoationsSet);
        assertEquals(3, wrapper.getAnnotations().size());
        assertFalse(wrapper.isAnnotationPresent(RequiresGuest.class));
        assertTrue(wrapper.isAnnotationPresent(SessionScoped.class));
    }

    @Test
    void badLambdaArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> new AnnotatedTypeWrapper<>(annotatedType, true,
                        Set.of(() -> SessionScoped.class),
                        Set.of(() -> RequiresGuest.class)));
        assertThrows(IllegalArgumentException.class,
                () -> new AnnotatedTypeWrapper<>(annotatedType, true,
                        Set.of(() -> RequiresGuest.class),
                        Set.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new AnnotatedTypeWrapper<>(annotatedType, true,
                        Set.of(),
                        Set.of(() -> RequiresGuest.class)));
    }

    @Test
    void overriddenAnnotation() {
        initializeStubs();
        when(annotatedType.getJavaClass()).thenReturn(Void.class);
        assertEquals(3, annotatedType.getAnnotations().size());
        Annotation shiroSecureAnnoations = getAnnotation(ShiroSecureAnnotated.class, ShiroSecureAnnotation.class);
        Annotation statelessAnnoations = getAnnotation(StatelessAnnotated.class, Stateless.class);
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, false,
                Set.of(shiroSecureAnnoations, statelessAnnoations),
                Set.of());
        assertEquals(2, wrapper.getAnnotations().size());
        assertTrue(wrapper.isAnnotationPresent(ShiroSecureAnnotation.class));
        assertTrue(wrapper.isAnnotationPresent(Stateless.class));
        assertEquals(Void.class, wrapper.getJavaClass());
    }

    @Test
    void decreaseAnnotationsToZero() {
        initializeStubs();
        assertEquals(3, annotatedType.getAnnotations().size());
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, false, Set.of(), Set.of());
        assertEquals(0, wrapper.getAnnotations().size());
    }

    private void initializeStubs() {
        when(annotatedType.getAnnotations()).thenReturn(Stream.of(Annotated.class.getDeclaredAnnotations())
                .collect(Collectors.toSet()));
    }

    private Annotation getAnnotation(Class<?> annotatedClass, Class<?> annotation) {
        return Arrays.stream(annotatedClass.getDeclaredAnnotations())
                .filter(a -> a.annotationType().equals(annotation))
                .findFirst()
                .orElse(null);
    }
}
