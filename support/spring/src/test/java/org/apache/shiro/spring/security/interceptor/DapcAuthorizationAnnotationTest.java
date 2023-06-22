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

import org.apache.shiro.authz.UnauthenticatedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * All the tests in the parent class are run.  This class only exists to ensure that a
 * DefaultAutoProxyCreator Spring AOP environment exists and enables annotations correctly as
 * documented in the Spring reference manual: 
 * <a href="http://static.springsource.org/spring/docs/3.0.x/spring-framework-reference/html/aop-api.html#aop-autoproxy">
 * Using the &quot;autoproxy&quot; facility</a>.
 *
 * @since 1.1
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration
public class DapcAuthorizationAnnotationTest extends AbstractAuthorizationAnnotationTest {

    @Test
    void testGuestInterfaceFailure() {
        assertThrows(UnauthenticatedException.class, () -> {
            bindUser();
            testService.guestInterface();
        });
    }

    @Test
    void testUserInterfaceFailure() {
        assertThrows(UnauthenticatedException.class, () -> {
            bindGuest();
            testService.userInterface();
        });
    }

    @Test
    void testAuthenticatedInterfaceFailure() {
        assertThrows(UnauthenticatedException.class, () -> {
            bindGuest();
            testService.authenticatedInterface();
        });
    }
}
