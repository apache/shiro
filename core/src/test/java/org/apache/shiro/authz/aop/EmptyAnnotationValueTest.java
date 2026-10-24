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

import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.config.ConfigurationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.lang.annotation.Annotation;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests that annotations without any roles or permissions only warn by default, and are rejected at startup when so configured.
 */
@ResourceLock("AuthorizationConfigPolicy.strictParsing")
public class EmptyAnnotationValueTest {

    private boolean strictParsing;

    @BeforeEach
    void saveStrictParsing() {
        strictParsing = AuthorizationConfigPolicy.isStrictParsing();
        AuthorizationConfigPolicy.setStrictParsing(false);
    }

    private static RequiresRoles roles(String... values) {
        return new RequiresRoles() {
            @Override
            public String[] value() {
                return values;
            }

            @Override
            public Logical logical() {
                return Logical.AND;
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
        };
    }

    private static RequiresPermissions permissions(String... values) {
        return new RequiresPermissions() {
            @Override
            public String[] value() {
                return values;
            }

            @Override
            public Logical logical() {
                return Logical.AND;
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }
        };
    }

    @AfterEach
    void restoreStrictParsing() {
        AuthorizationConfigPolicy.setStrictParsing(strictParsing);
    }

    @Test
    public void handlersOnlyWarnByDefault() {
        // the empty check does not stop the call, it only fails later for lack of a subject
        assertThatThrownBy(() -> new RoleAnnotationHandler().assertAuthorized(roles()))
                .isNotInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> new PermissionAnnotationHandler().assertAuthorized(permissions()))
                .isNotInstanceOf(ConfigurationException.class);
    }

    @Test
    public void handlersRejectEmptyWhenStrict() {
        AuthorizationConfigPolicy.setStrictParsing(true);
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> new RoleAnnotationHandler().assertAuthorized(roles()));
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> new PermissionAnnotationHandler().assertAuthorized(permissions()));
    }

    @Test
    public void emptyAnnotationsOnlyWarnByDefault() {
        assertThatCode(() -> {
            AuthorizationConfigPolicy.validate(roles());
            AuthorizationConfigPolicy.validate(permissions());
        }).doesNotThrowAnyException();
    }

    @Test
    public void emptyAnnotationsFailWhenStrict() {
        AuthorizationConfigPolicy.setStrictParsing(true);
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> AuthorizationConfigPolicy.validate(roles()));
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> AuthorizationConfigPolicy.validate(permissions()));
    }

    @Test
    public void nonEmptyAnnotationsPassWhenStrict() {
        AuthorizationConfigPolicy.setStrictParsing(true);
        assertThatCode(() -> {
            AuthorizationConfigPolicy.validate(roles("admin"));
            AuthorizationConfigPolicy.validate(permissions("user:read"));
        }).doesNotThrowAnyException();
    }
}
