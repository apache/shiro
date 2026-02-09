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
import jakarta.ejb.Stateless;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

import jakarta.enterprise.context.SessionScoped;
import jakarta.enterprise.inject.spi.AnnotatedType;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;

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
        assertThat(wrapper.getAnnotations()).isEmpty();
    }

    @Test
    void noAdditionalAnnotations() {
        initializeStubs();
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType);
        assertThat(wrapper.getAnnotations()).hasSize(3);
    }

    @Test
    @SuppressWarnings("MagicNumber")
    void twoAdditionalAnnotations() {
        initializeStubs();
        Annotation shiroSecureAnnotation = getAnnotation(ShiroSecureAnnotated.class, ShiroSecureAnnotation.class);
        Annotation statelessAnnotation = getAnnotation(StatelessAnnotated.class, Stateless.class);
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, shiroSecureAnnotation, statelessAnnotation);
        assertThat(wrapper.getAnnotations()).hasSize(5);
        assertThat(wrapper.isAnnotationPresent(ShiroSecureAnnotation.class)).isTrue();
        assertThat(wrapper.isAnnotationPresent(Stateless.class)).isTrue();
        assertThat(wrapper.isAnnotationPresent(RequiresAuthentication.class)).isTrue();
        assertThat(wrapper.isAnnotationPresent(RequiresGuest.class)).isTrue();
        assertThat(wrapper.isAnnotationPresent(RequiresPermissions.class)).isTrue();
    }

    @Test
    void removeAnnotations() {
        initializeStubs();
        Set<Annotation> sessionScopeAnnoationsSet = Set.of(getAnnotation(SessionScopedAnnotated.class, SessionScoped.class));
        Set<Annotation> requiresGuestAnnoationsSet = Set.of(getAnnotation(Annotated.class, RequiresGuest.class));
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, true, sessionScopeAnnoationsSet, requiresGuestAnnoationsSet);
        assertThat(wrapper.getAnnotations()).hasSize(3);
        assertThat(wrapper.isAnnotationPresent(RequiresGuest.class)).isFalse();
        assertThat(wrapper.isAnnotationPresent(SessionScoped.class)).isTrue();
    }

    @Test
    void badLambdaArgument() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new AnnotatedTypeWrapper<>(annotatedType, true,
                Set.of(() -> SessionScoped.class),
                Set.of(() -> RequiresGuest.class)));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new AnnotatedTypeWrapper<>(annotatedType, true,
                Set.of(() -> RequiresGuest.class),
                Set.of()));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new AnnotatedTypeWrapper<>(annotatedType, true,
                Set.of(),
                Set.of(() -> RequiresGuest.class)));
    }

    @Test
    void overriddenAnnotation() {
        initializeStubs();
        when(annotatedType.getJavaClass()).thenReturn(Void.class);
        assertThat(annotatedType.getAnnotations()).hasSize(3);
        Annotation shiroSecureAnnotations = getAnnotation(ShiroSecureAnnotated.class, ShiroSecureAnnotation.class);
        Annotation statelessAnnotations = getAnnotation(StatelessAnnotated.class, Stateless.class);
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, false,
                Set.of(shiroSecureAnnotations, statelessAnnotations),
                Set.of());
        assertThat(wrapper.getAnnotations()).hasSize(2);
        assertThat(wrapper.isAnnotationPresent(ShiroSecureAnnotation.class)).isTrue();
        assertThat(wrapper.isAnnotationPresent(Stateless.class)).isTrue();
        assertThat(wrapper.getJavaClass()).isEqualTo(Void.class);
    }

    @Test
    void decreaseAnnotationsToZero() {
        initializeStubs();
        assertThat(annotatedType.getAnnotations()).hasSize(3);
        var wrapper = new AnnotatedTypeWrapper<>(annotatedType, false, Set.of(), Set.of());
        assertThat(wrapper.getAnnotations()).isEmpty();
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
