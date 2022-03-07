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
package org.apache.shiro.authc.pam;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.MergableAuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;


public class FirstSuccessfulStrategyTest {

    private FirstSuccessfulStrategy strategy;

    @Before
    public void setUp() {
        strategy = new FirstSuccessfulStrategy();
        strategy.setStopAfterFirstSuccess(true);
    }

    @Test
    public void beforeAllAttempts() {
        AuthenticationInfo authenticationInfo = strategy.beforeAllAttempts(null, null);
        assertNull(authenticationInfo);
    }

    @Test
    public void testMergeWithValidAggregateInfo() {
        AuthenticationInfo aggregate = new MergableAuthenticationInfo() {
            @Override
            public void merge(AuthenticationInfo info) {

            }

            @Override
            public PrincipalCollection getPrincipals() {
                return new SimplePrincipalCollection("principals", "realmName");
            }

            @Override
            public Object getCredentials() {
                return null;
            }
        };
        AuthenticationInfo mergeResult = strategy.merge(new SimpleAuthenticationInfo(), aggregate);
        assertEquals(aggregate, mergeResult);
    }

    @Test
    public void testMergeWithInvalidAggregateInfo() {
        AuthenticationInfo aggregate = new MergableAuthenticationInfo() {
            @Override
            public void merge(AuthenticationInfo info) {

            }

            @Override
            public PrincipalCollection getPrincipals() {
                return new SimplePrincipalCollection();
            }

            @Override
            public Object getCredentials() {
                return null;
            }
        };

        AuthenticationInfo authInfo = new SimpleAuthenticationInfo();
        AuthenticationInfo mergeResult = strategy.merge(authInfo, aggregate);
        assertEquals(authInfo, mergeResult);
        AuthenticationInfo info = strategy.beforeAllAttempts(null, null);
        assertNull(info);
    }

    @Test 
    public void testBeforeAttemptNull() {
        assertNull(strategy.beforeAttempt(null, null, null));
    }

    @Test
    public void testBeforeAttemptEmptyPrincipal() {
        AuthenticationInfo aggregate = new SimpleAuthenticationInfo();
        assertEquals(strategy.beforeAttempt(null, null, aggregate), aggregate);
    }

    @Test
    public void testBeforeAttemptEmptyList() {
        SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
        AuthenticationInfo aggregate = new SimpleAuthenticationInfo(principalCollection, null);
        assertEquals(strategy.beforeAttempt(null, null, aggregate), aggregate);
    }

    @Test (expected=ShortCircuitIterationException.class)
    public void testBeforeAttemptStopAfterFirstSuccess() {
        AuthenticationInfo aggregate = new SimpleAuthenticationInfo("principal", null, "a-realm-name");
        strategy.beforeAttempt(null, null, aggregate);
    }
}
