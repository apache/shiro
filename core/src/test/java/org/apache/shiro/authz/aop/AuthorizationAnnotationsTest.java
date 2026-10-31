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
package org.apache.shiro.authz.aop;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.apache.shiro.aop.DefaultAnnotationResolver;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class AuthorizationAnnotationsTest {
    private static final int ALL_TYPES = 8;

    @Test
    void registryContainsShiroAndJsr250Types() {
        assertThat(AuthorizationAnnotations.shiroTypes()).containsExactly(RequiresRoles.class, RequiresPermissions.class,
                RequiresAuthentication.class, RequiresUser.class, RequiresGuest.class);
        assertThat(AuthorizationAnnotations.allTypes()).hasSize(ALL_TYPES)
                .containsAll(AuthorizationAnnotations.shiroTypes()).contains(RolesAllowed.class, PermitAll.class, DenyAll.class);
    }

    @Test
    void handlersAndInterceptorsMatchTheirAnnotationType() {
        for (Class<? extends Annotation> type : AuthorizationAnnotations.allTypes()) {
            assertThat(handler(type).getAnnotationClass()).isEqualTo(type);
        }
        assertThatIllegalArgumentException().isThrownBy(() -> handler(Override.class));
    }

    @Test
    void interceptorsShareTheResolver() {
        DefaultAnnotationResolver resolver = new DefaultAnnotationResolver();
        List<AuthorizingAnnotationMethodInterceptor> interceptors =
                AuthorizationAnnotations.createMethodInterceptors(resolver, AuthorizationAnnotations.allTypes());
        assertThat(interceptors).hasSize(ALL_TYPES).allSatisfy(i -> assertThat(i.getResolver()).isSameAs(resolver));
        assertThat(new AnnotationsAuthorizingMethodInterceptor() { }.getMethodInterceptors()).hasSize(5);
    }

    private static AuthorizingAnnotationHandler handler(Class<? extends Annotation> type) {
        return AuthorizationAnnotations.createMethodInterceptors(null, List.of(type))
                .get(0).getHandler();
    }
}
