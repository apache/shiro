/*
 * Copyright (c) 2019 Nova Ordis LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.authc.pam;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.MergableAuthenticationInfo;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by lei.li4 on 2019/1/23
 */
public class FirstSuccessfulStrategyTest {

    private FirstSuccessfulStrategy strategy;

    @Before
    public void setUp() {
        strategy = new FirstSuccessfulStrategy();
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
    }

}
