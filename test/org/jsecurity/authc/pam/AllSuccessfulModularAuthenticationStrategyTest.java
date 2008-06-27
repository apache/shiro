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
package org.jsecurity.authc.pam;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.realm.AuthorizingRealm;
import org.jsecurity.realm.Realm;
import org.jsecurity.realm.SimpleAccountRealm;
import org.jsecurity.subject.PrincipalCollection;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 29, 2008
 * Time: 12:18:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class AllSuccessfulModularAuthenticationStrategyTest {

    private AllSuccessfulModularAuthenticationStrategy strategy;

    @Before
    public void setUp() {
        strategy = new AllSuccessfulModularAuthenticationStrategy();
    }

    @Test
    public void beforeAllAttempts() {
        Account account = strategy.beforeAllAttempts(null, null);
        assertNotNull(account);
    }

    @Test
    public void beforeAttemptSupportingToken() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.init();
    }

    @Test(expected = UnsupportedTokenException.class)
    public void beforeAttemptRealmDoesntSupportToken() {
        Realm notSupportingRealm = new AuthorizingRealm() {

            public boolean supports(AuthenticationToken token) {
                return false;
            }

            protected AuthorizingAccount doGetAccount(PrincipalCollection principal) {
                return null;
            }

            protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
                return null;
            }
        };

        strategy.beforeAttempt(notSupportingRealm, null, null);
    }


}
