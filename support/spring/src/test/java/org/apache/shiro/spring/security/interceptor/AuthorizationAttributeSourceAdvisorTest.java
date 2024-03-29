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
package org.apache.shiro.spring.security.interceptor;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthorizationAttributeSourceAdvisorTest {

    static class Secured {
        @RequiresAuthentication
        public void secureMethod() {
        }

        public void unsecuredMethod() {
        }
    }

    interface ServiceInterface {
        @RequiresAuthentication
        String secureMethod();

        String unsecuredMethod();
    }

    static class ServiceImpl implements ServiceInterface {

        @Override
        public String secureMethod() {
            return "";
        }

        @Override
        public String unsecuredMethod() {
            return "";
        }
    }

    @RequiresAuthentication
    interface SafeServiceInterface {
        String someMethod();
    }

    static class SafeServiceImpl implements SafeServiceInterface {

        @Override
        public String someMethod() {
            return "";
        }
    }

    @Test
    void matches() throws NoSuchMethodException {
        assertTrue(
                new AuthorizationAttributeSourceAdvisor().matches(
                        Secured.class.getDeclaredMethod("secureMethod"), Secured.class
                ),
                "the method is annotated, should match");
        assertFalse(
                new AuthorizationAttributeSourceAdvisor().matches(
                        Secured.class.getDeclaredMethod("unsecuredMethod"), Secured.class
                ),
                "the method is not annotated, should not match");

        assertTrue(
                new AuthorizationAttributeSourceAdvisor().matches(
                        ServiceInterface.class.getDeclaredMethod("secureMethod"), ServiceImpl.class
                ),
                "the method declaration is annotated in the interface, should match");
        assertFalse(
                new AuthorizationAttributeSourceAdvisor().matches(
                        ServiceInterface.class.getDeclaredMethod("unsecuredMethod"), ServiceImpl.class
                ),
                "not annotated method, should not match");

        assertTrue(
                new AuthorizationAttributeSourceAdvisor().matches(
                        SafeServiceInterface.class.getDeclaredMethod("someMethod"), SafeServiceInterface.class
                ),
                "the method declaration is in the interface with type-annotation, should match");
        assertTrue(
                new AuthorizationAttributeSourceAdvisor().matches(
                        SafeServiceImpl.class.getDeclaredMethod("someMethod"), SafeServiceImpl.class
                ),
                "the method declaration is in the interface with type-annotation, should match");

    }

}
