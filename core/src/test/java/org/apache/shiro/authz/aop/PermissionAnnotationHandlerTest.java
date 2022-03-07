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
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test cases for the {@link PermissionAnnotationHandler} class.
 */
public class PermissionAnnotationHandlerTest extends SecurityManagerTestSupport {

    //Added to satisfy SHIRO-146

    @Test
    public void testGuestSinglePermissionAssertion() {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();

        Annotation requiresPermissionAnnotation = new RequiresPermissions() {
            @Override
            public String[] value() {
                return new String[]{"test:test"};
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }

	    @Override
        public Logical logical() {
		return Logical.AND;
	    }
        };

        assertThrows(UnauthenticatedException.class, () -> handler.assertAuthorized(requiresPermissionAnnotation));
    }

    //Added to satisfy SHIRO-146

    @Test
    public void testGuestMultiplePermissionAssertion() {
        PermissionAnnotationHandler handler = new PermissionAnnotationHandler();

        Annotation requiresPermissionAnnotation = new RequiresPermissions() {
            @Override
            public String[] value() {
                return new String[]{"test:test", "test2:test2"};
            }

            @Override
            public Class<? extends Annotation> annotationType() {
                return RequiresPermissions.class;
            }
            
	    @Override
        public Logical logical() {
		return Logical.AND;
	    }
        };

        assertThrows(UnauthenticatedException.class, () -> handler.assertAuthorized(requiresPermissionAnnotation));
    }

}
