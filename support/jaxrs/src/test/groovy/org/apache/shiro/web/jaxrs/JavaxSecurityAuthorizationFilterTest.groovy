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
package org.apache.shiro.web.jaxrs

import org.apache.shiro.authz.annotation.RequiresGuest
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.junit.Assert
import org.junit.Test

import javax.annotation.security.PermitAll
import javax.annotation.security.RolesAllowed
import javax.ws.rs.container.ContainerRequestContext
import java.lang.annotation.Annotation

import static org.easymock.EasyMock.*
import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.*

/**
 * Tests for {@link JavaxSecurityAuthorizationFilter}.
 * @since 1.4.0
 */
class JavaxSecurityAuthorizationFilterTest {

    @Test
    void simpleTest() {

        List<Annotation> annotationSpecs = new ArrayList<Annotation>();
        annotationSpecs.add(JavaxAnnotatedStub.getAnnotation(PermitAll.class))
        annotationSpecs.add(JavaxAnnotatedStub.getMethod("rolesAllowed").getAnnotation(RolesAllowed.class))

        def requestContext = mock(ContainerRequestContext)
        def subject = mock(Subject)
        subject.checkRole("Role1")

        try {
            ThreadContext.bind(subject)

            replay requestContext, subject

            new JavaxSecurityAuthorizationFilter(annotationSpecs).filter(requestContext)

            verify requestContext, subject
        }
        finally {
            ThreadContext.unbindSubject()
        }
    }

    @Test
    void unhandledAnnotationTest() {
        List<Annotation> annotationSpecs = new ArrayList<Annotation>();
        annotationSpecs.add(JavaxAnnotatedStub.getMethod("requiresGuest").getAnnotation(RequiresGuest.class))

        def requestContext = mock(ContainerRequestContext)
        def subject = mock(Subject)

        try {
            ThreadContext.bind(subject)

            replay requestContext, subject

            new JavaxSecurityAuthorizationFilter(annotationSpecs).filter(requestContext)
            Assert.fail("expected IllegalArgumentException")
        }
        catch(IllegalArgumentException e){
            assertThat e.getMessage(), stringContainsInOrder(RequiresGuest.getName())
        }
        finally {

            verify requestContext, subject
            ThreadContext.unbindSubject()
        }
    }
}
