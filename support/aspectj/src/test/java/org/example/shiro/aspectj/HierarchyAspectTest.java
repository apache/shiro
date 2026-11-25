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
package org.example.shiro.aspectj;

import java.util.stream.Stream;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.example.shiro.aspectj.HierarchyFixtures.AddsMethodToSecuredBase;
import org.example.shiro.aspectj.HierarchyFixtures.ComposedOnMethod;
import org.example.shiro.aspectj.HierarchyFixtures.ComposedOnType;
import org.example.shiro.aspectj.HierarchyFixtures.ImplementsSecuredMethod;
import org.example.shiro.aspectj.HierarchyFixtures.OverridesSecuredMethod;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Named.named;

/**
 * Annotations that only the hierarchy lookup can find are enforced.
 * Each call runs as its own Subject, bound to the current thread only, so the tests can run in parallel.
 */
class HierarchyAspectTest {
    private static final SecurityManager SECURITY_MANAGER =
            new BasicIniEnvironment("classpath:shiroDummyServiceTest.ini").getSecurityManager();

    private final Subject subject = new Subject.Builder(SECURITY_MANAGER).buildSubject();

    static Stream<Named<Runnable>> securedCalls() {
        return Stream.of(
                named("annotation on an interface method", () -> new ImplementsSecuredMethod().run()),
                named("annotation on an overridden superclass method", () -> new OverridesSecuredMethod().run()),
                named("new method in a subclass of an annotated class", () -> new AddsMethodToSecuredBase().run()),
                named("composed annotation on a method", () -> new ComposedOnMethod().run()),
                named("composed annotation on a class", () -> new ComposedOnType().run()),
                named("static method of a class with a composed annotation", ComposedOnType::runStatic));
    }

    @ParameterizedTest
    @MethodSource("securedCalls")
    void anonymousIsRejected(Runnable call) {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> subject.execute(call));
    }

    @ParameterizedTest
    @MethodSource("securedCalls")
    void adminIsAllowed(Runnable call) {
        subject.login(new UsernamePasswordToken("root", "secret"));
        assertThatCode(() -> subject.execute(call)).doesNotThrowAnyException();
    }
}
