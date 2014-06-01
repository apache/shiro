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
package org.apache.shiro.authc.strategy;

import org.apache.shiro.account.Account;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.DefaultCompositeAccount;
import org.apache.shiro.realm.Realm;

/**
 * @since 2.0
 */
public class AllRealmsSuccessfulStrategy implements AuthenticationStrategy {

    public Account execute(AuthenticationAttempt attempt) throws AuthenticationException {

        AuthenticationToken token = attempt.getAuthenticationToken();

        String firstAccountRealmName = null;
        Account firstAccount = null;
        DefaultCompositeAccount compositeAccount = null;

        for(Realm realm : attempt.getRealms()) {

            if (realm.supports(token)) {

                // If the realm throws an exception, the loop will short circuit and this method will
                // return.  As an 'all successful' strategy, if there is even a single exception thrown by any of the
                // supported realms, the authentication attempt is unsuccessful.
                //
                // This particular implementation also favors short circuiting immediately (instead of trying all
                // realms and then aggregating all potential exceptions) because continuing to access additional
                // account stores is likely to incur unnecessary / undesirable I/O for most apps.
                Account account = realm.authenticateAccount(token);

                if (account != null) {
                    if (firstAccount == null) {
                        firstAccount = account;
                        firstAccountRealmName = realm.getName();
                    } else {
                        if (compositeAccount == null) {
                            compositeAccount = new DefaultCompositeAccount();
                            compositeAccount.appendRealmAccount(firstAccountRealmName, firstAccount);
                        }
                        compositeAccount.appendRealmAccount(realm.getName(), account);
                    }
                }
            }
        }

        if (compositeAccount != null) {
            return compositeAccount;
        }

        return firstAccount;
    }
}
