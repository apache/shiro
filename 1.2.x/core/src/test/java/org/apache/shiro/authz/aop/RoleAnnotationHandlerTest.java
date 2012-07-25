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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.Test;

import java.lang.annotation.Annotation;

/**
 * Test cases for the {@link RoleAnnotationHandler} class.
 */
public class RoleAnnotationHandlerTest extends SecurityManagerTestSupport {
    private Subject subject;

    //Added to satisfy SHIRO-146

    @Test(expected = UnauthenticatedException.class)
    public void testGuestSingleRoleAssertion() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();

        Annotation requiresRolesAnnotation = new RequiresRoles() {
            public String[] value() {
                return new String[]{"blah"};
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
	    public Logical logical() {
		return Logical.AND;
	    }
        };

        handler.assertAuthorized(requiresRolesAnnotation);
    }

    //Added to satisfy SHIRO-146

    @Test(expected = UnauthenticatedException.class)
    public void testGuestMultipleRolesAssertion() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();

        Annotation requiresRolesAnnotation = new RequiresRoles() {
            public String[] value() {
                return new String[]{"blah", "blah2"};
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
	    public Logical logical() {
		return Logical.AND;
	    }
        };

        handler.assertAuthorized(requiresRolesAnnotation);
    }
    
    @Test
    public void testOneOfTheRolesRequired() throws Throwable {
	subject = createMock(Subject.class);
	expect(subject.hasRole("blah")).andReturn(true);
	expect(subject.hasRole("blah2")).andReturn(false);
        replay(subject);
	RoleAnnotationHandler handler = new RoleAnnotationHandler() {
            @Override
	    protected Subject getSubject() {
        	return subject;
            }
        };

        Annotation requiresRolesAnnotation = new RequiresRoles() {
            public String[] value() {
                return new String[]{"blah", "blah2"};
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
	    public Logical logical() {
		return Logical.OR;
	    }
        };
        handler.assertAuthorized(requiresRolesAnnotation);
    }
}
