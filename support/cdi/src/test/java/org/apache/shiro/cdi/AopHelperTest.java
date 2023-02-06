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

import java.lang.annotation.Annotation;
import java.util.List;
import javax.validation.constraints.NotNull;
import lombok.SneakyThrows;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.authz.aop.AuthenticatedAnnotationHandler;
import org.apache.shiro.authz.aop.UserAnnotationHandler;
import org.apache.shiro.cdi.AopHelper.SecurityInterceptor;
import static org.apache.shiro.cdi.AopHelper.autorizationAnnotationClasses;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * AOP Helper unit test
 */
class AopHelperTest {
    private List<AopHelper.SecurityInterceptor> interceptors;

    @RequiresUser
    static class Annotated {
        @RequiresAuthentication
        public void method() { }
    }

    @ShiroSecureAnnotation
    public class NotAnnotated {
        @NotNull
        public void method() { }
    }

    @SneakyThrows
    void createInterceptors() {
        interceptors = AopHelper.createSecurityInterceptors(Annotated.class.getMethod("method"), Annotated.class);
    }

    @Test
    @SneakyThrows
    void numberOfInterceptors() {
        createInterceptors();
        assertEquals(2, interceptors.size());
    }

    @Test
    void checkInterceptors() {
        try (var mc = mockConstruction(UserAnnotationHandler.class)) {
            try (var mc2 = mockConstruction(AuthenticatedAnnotationHandler.class)) {
                createInterceptors();
                interceptors.forEach(SecurityInterceptor::intercept);
                verify(mc.constructed().get(0), times(1)).assertAuthorized(any());
                verify(mc2.constructed().get(0), times(1)).assertAuthorized(any());
            }
        }
    }

    @Test
    @SneakyThrows
    void checkNotAnnotated() {
        assertEquals(0, AopHelper.createSecurityInterceptors(NotAnnotated.class.getMethod("method"),
                NotAnnotated.class).size());
    }

    @Test
    @SneakyThrows
    @SuppressWarnings("MagicNumber")
    void checkAllAnnotationTypes() {
        assertEquals(5, autorizationAnnotationClasses.keySet().stream().distinct().count());
        for (Class<? extends Annotation> clz : autorizationAnnotationClasses.keySet()) {
            assertEquals(clz, autorizationAnnotationClasses.get(clz).call().getAnnotationClass());
        }
    }
}
