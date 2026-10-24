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
package org.apache.shiro.web.filter.authz;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.authz.aop.AuthorizingAnnotationHandler.AuthorizationConfigPolicy;
import org.apache.shiro.config.ConfigurationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.easymock.EasyMock.createNiceMock;

/**
 * Tests that the {@code perms} and {@code roles} filters warn and allow by default, and reject the configuration
 * at startup when so configured, if no permissions or roles are configured.
 */
@ResourceLock("AuthorizationConfigPolicy.strictParsing")
class EmptyAuthorizationConfigFilterTest {
    private boolean strictParsing;
    private final ServletRequest request = createNiceMock(ServletRequest.class);
    private final ServletResponse response = createNiceMock(ServletResponse.class);

    @BeforeEach
    void bindSubject() {
        strictParsing = AuthorizationConfigPolicy.isStrictParsing();
        AuthorizationConfigPolicy.setStrictParsing(false);
        Subject subject = createNiceMock(Subject.class);
        ThreadContext.bind(subject);
    }

    @AfterEach
    void unbind() {
        AuthorizationConfigPolicy.setStrictParsing(strictParsing);
        ThreadContext.remove();
    }

    @FunctionalInterface
    private interface AccessCheck {
        boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
                throws Exception;
    }

    static Stream<Arguments> filters() {
        PermissionsAuthorizationFilter perms = new PermissionsAuthorizationFilter();
        RolesAuthorizationFilter roles = new RolesAuthorizationFilter();
        return Stream.of(
                Arguments.of(perms, (AccessCheck) perms::isAccessAllowed),
                Arguments.of(roles, (AccessCheck) roles::isAccessAllowed));
    }

    @ParameterizedTest
    @MethodSource("filters")
    void allowsEmptyConfigByDefault(AuthorizationFilter filter, AccessCheck check) throws Exception {
        filter.processPathConfig("/admin/**", null);
        assertThat(check.isAccessAllowed(request, response, null)).isTrue();
        assertThat(check.isAccessAllowed(request, response, new String[0])).isTrue();
    }

    @ParameterizedTest
    @MethodSource("filters")
    void rejectsEmptyConfigAtStartupWhenStrict(AuthorizationFilter filter, AccessCheck check) {
        AuthorizationConfigPolicy.setStrictParsing(true);
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> filter.processPathConfig("/admin/**", null));
        assertThatExceptionOfType(ConfigurationException.class)
                .isThrownBy(() -> filter.processPathConfig("/admin/**", ""));
    }

    @ParameterizedTest
    @MethodSource("filters")
    void acceptsConfigWhenStrict(AuthorizationFilter filter, AccessCheck check) {
        AuthorizationConfigPolicy.setStrictParsing(true);
        assertThatCode(() -> filter.processPathConfig("/admin/**", "admin")).doesNotThrowAnyException();
    }
}
