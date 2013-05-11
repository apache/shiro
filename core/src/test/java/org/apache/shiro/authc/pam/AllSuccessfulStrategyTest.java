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

import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.PrincipalCollection;


public class AllSuccessfulStrategyTest {

    private AllSuccessfulStrategy strategy;

    @Before
    public void setUp() {
        strategy = new AllSuccessfulStrategy();
    }

    @Test
    public void beforeAllAttempts() {
        AuthenticationInfo info = strategy.beforeAllAttempts(null, null);
        assertNotNull(info);
    }

    @Test
    public void beforeAttemptSupportingToken() {
        new SimpleAccountRealm();
    }

    @Test(expected = UnsupportedTokenException.class)
    public void beforeAttemptRealmDoesntSupportToken() {
        Realm notSupportingRealm = new AuthorizingRealm() {

            public boolean supports(AuthenticationToken token) {
                return false;
            }

            protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
                return null;
            }

            protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
                return null;
            }

        };

        strategy.beforeAttempt(notSupportingRealm, null, null);
    }


}
