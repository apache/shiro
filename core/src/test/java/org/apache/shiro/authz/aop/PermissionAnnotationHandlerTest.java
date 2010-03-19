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
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.Test;

import java.lang.annotation.Annotation;

/**
 * Test cases for the {@link PermissionAnnotationHandler} class.
 */
public class PermissionAnnotationHandlerTest extends SecurityManagerTestSupport {

    @Test(expected = UnauthenticatedException.class)
    public void testGuestSinglePermissionAssertion() throws Throwable {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();

        Annotation requiresPermissionAnnotation = new RequiresPermissions() {
            public String value() {
                return "test:test";
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }
        };

        handler.assertAuthorized(requiresPermissionAnnotation);
    }

    @Test(expected = UnauthenticatedException.class)
    public void testGuestMultiplePermissionAssertion() throws Throwable {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();

        Annotation requiresPermissionAnnotation = new RequiresPermissions() {
            public String value() {
                return "test:test, test2:test2";
            }

            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }
        };

        handler.assertAuthorized(requiresPermissionAnnotation);
    }

}
