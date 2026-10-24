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
package org.apache.shiro.ejb;

import jakarta.ejb.Stateless;
import jakarta.enterprise.inject.spi.AnnotatedType;
import jakarta.enterprise.inject.spi.ProcessAnnotatedType;

import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ShiroEjbSecurityExtensionTest {
    @RequiresUser
    interface Secured {
    }

    @Stateless
    static class SecuredViaInterface implements Secured {
    }

    @Stateless
    static class Unsecured {
    }

    @Test
    @SuppressWarnings("unchecked")
    void ejbSecuredViaInterfaceGetsInterceptorBinding() {
        var pat = mock(ProcessAnnotatedType.class);
        var type = mock(AnnotatedType.class);
        when(type.getJavaClass()).thenReturn(SecuredViaInterface.class);
        when(pat.getAnnotatedType()).thenReturn(type);
        new ShiroEjbSecurityExtension().addInheritedSecurity(pat);
        var captor = ArgumentCaptor.forClass(AnnotatedType.class);
        verify(pat).setAnnotatedType(captor.capture());
        assertThat(captor.getValue().getAnnotations())
                .anyMatch(ann -> ann.annotationType().getSimpleName().equals("ShiroSecureAnnotation"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void unsecuredEjbIsLeftAlone() {
        var pat = mock(ProcessAnnotatedType.class);
        var type = mock(AnnotatedType.class);
        when(type.getJavaClass()).thenReturn(Unsecured.class);
        when(pat.getAnnotatedType()).thenReturn(type);
        new ShiroEjbSecurityExtension().addInheritedSecurity(pat);
        verify(pat, never()).setAnnotatedType(any());
    }
}
