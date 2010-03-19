/*
 * Copyright 2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.authz.aop;

import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.Test;

import java.lang.annotation.Annotation;

/**
 * Test cases for the {@link RoleAnnotationHandler} class.
 */
public class RoleAnnotationHandlerTest extends SecurityManagerTestSupport {

    //Added to satisfy SHIRO-146

    @Test(expected = UnauthenticatedException.class)
    public void testGuestSingleRoleAssertion() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();

        Annotation requiresRolesAnnotation = new RequiresRoles() {
            public String value() {
                return "blah";
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
        };

        handler.assertAuthorized(requiresRolesAnnotation);
    }

    //Added to satisfy SHIRO-146

    @Test(expected = UnauthenticatedException.class)
    public void testGuestMultipleRolesAssertion() throws Throwable {
        RoleAnnotationHandler handler = new RoleAnnotationHandler();

        Annotation requiresRolesAnnotation = new RequiresRoles() {
            public String value() {
                return "blah, blah2";
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresRoles.class;
            }
        };

        handler.assertAuthorized(requiresRolesAnnotation);
    }
}
