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

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.jupiter.api.Test;

import jakarta.annotation.security.DenyAll;
import java.lang.annotation.Annotation;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * Test cases for the {@link DenyAllAnnotationHandler} class.
 */
public class DenyAllAnnotationHandlerTest extends SecurityManagerTestSupport {
    private Subject subject;

    @Test
    void testGuestSingleRoleAssertion() throws Throwable {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            DenyAllAnnotationHandler handler = new DenyAllAnnotationHandler();

            Annotation denyAllAnnotation = new DenyAll() {
                @Override
                public Class<? extends Annotation> annotationType() {
                    return DenyAll.class;
                }
            };

            handler.assertAuthorized(denyAllAnnotation);
        });
    }

    @Test
    void testOneOfTheRolesRequired() throws Throwable {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            subject = createMock(Subject.class);
            expect(subject.hasRole("blah")).andReturn(true);
            replay(subject);
            DenyAllAnnotationHandler handler = new DenyAllAnnotationHandler() {
                @Override
                protected Subject getSubject() {
                    return subject;
                }
            };

            Annotation denyAllAnnotation = new DenyAll() {
                @Override
                public Class<? extends Annotation> annotationType() {
                    return DenyAll.class;
                }
            };
            handler.assertAuthorized(denyAllAnnotation);
        });
    }
}
