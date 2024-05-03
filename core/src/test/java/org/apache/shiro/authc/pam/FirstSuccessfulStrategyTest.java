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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;


public class FirstSuccessfulStrategyTest {

    private FirstSuccessfulStrategy strategy;

    @BeforeEach
    public void setUp() {
        strategy = new FirstSuccessfulStrategy();
        strategy.setStopAfterFirstSuccess(true);
    }

    @Test
    void beforeAllAttempts() {
        AuthenticationInfo authenticationInfo = strategy.beforeAllAttempts(null, null);
        assertThat(authenticationInfo).isNull();
    }

    @Test
    void testMergeWithValidAggregateInfo() {
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
        assertThat(mergeResult).isEqualTo(aggregate);
    }

    @Test
    void testMergeWithInvalidAggregateInfo() {
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
        assertThat(mergeResult).isEqualTo(authInfo);
        AuthenticationInfo info = strategy.beforeAllAttempts(null, null);
        assertThat(info).isNull();
    }

    @Test
    void testBeforeAttemptNull() {
        assertThat(strategy.beforeAttempt(null, null, null)).isNull();
    }

    @Test
    void testBeforeAttemptEmptyPrincipal() {
        AuthenticationInfo aggregate = new SimpleAuthenticationInfo();
        assertThat(aggregate).isEqualTo(strategy.beforeAttempt(null, null, aggregate));
    }

    @Test
    void testBeforeAttemptEmptyList() {
        SimplePrincipalCollection principalCollection = new SimplePrincipalCollection();
        AuthenticationInfo aggregate = new SimpleAuthenticationInfo(principalCollection, null);
        assertThat(aggregate).isEqualTo(strategy.beforeAttempt(null, null, aggregate));
    }

    @Test
    void testBeforeAttemptStopAfterFirstSuccess() {
        assertThatExceptionOfType(ShortCircuitIterationException.class).isThrownBy(() -> {
            AuthenticationInfo aggregate = new SimpleAuthenticationInfo("principal", null, "a-realm-name");
            strategy.beforeAttempt(null, null, aggregate);
        });
    }
}
