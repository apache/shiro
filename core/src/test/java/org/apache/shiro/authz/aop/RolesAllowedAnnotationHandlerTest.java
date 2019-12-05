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
import org.junit.Test;

import javax.annotation.security.RolesAllowed;
import java.lang.annotation.Annotation;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * Test cases for the {@link RolesAllowedAnnotationHandler} class.
 */
public class RolesAllowedAnnotationHandlerTest extends SecurityManagerTestSupport {
    private Subject subject;

    @Test(expected = UnauthenticatedException.class)
    public void testGuestSingleRoleAssertion() throws Throwable {
        RolesAllowedAnnotationHandler handler = new RolesAllowedAnnotationHandler();

        Annotation rolesAllowedAnnotation = new RolesAllowed() {
            public String[] value() {
                return new String[]{"blah"};
            }

            public Class<? extends Annotation> annotationType() {
                return RolesAllowed.class;
            }
        };

        handler.assertAuthorized(rolesAllowedAnnotation);
    }

    @Test(expected = UnauthenticatedException.class)
    public void testGuestMultipleRolesAssertion() throws Throwable {
        RolesAllowedAnnotationHandler handler = new RolesAllowedAnnotationHandler();

        Annotation rolesAllowedAnnotation = new RolesAllowed() {
            public String[] value() {
                return new String[]{"blah", "blah2"};
            }

            public Class<? extends Annotation> annotationType() {
                return RolesAllowed.class;
            }
        };

        handler.assertAuthorized(rolesAllowedAnnotation);
    }

    @Test
    public void testOneOfTheRolesRequired() throws Throwable {
        subject = createMock(Subject.class);
        expect(subject.hasRole("blah")).andReturn(true);
        expect(subject.hasRole("blah2")).andReturn(false);
        replay(subject);
        RolesAllowedAnnotationHandler handler = new RolesAllowedAnnotationHandler() {
            @Override
            protected Subject getSubject() {
                return subject;
            }
        };

        Annotation rolesAllowedAnnotation = new RolesAllowed() {
            public String[] value() {
                return new String[]{"blah", "blah2"};
            }

            public Class<? extends Annotation> annotationType() {
                return RolesAllowed.class;
            }
        };
        handler.assertAuthorized(rolesAllowedAnnotation);
    }
}
