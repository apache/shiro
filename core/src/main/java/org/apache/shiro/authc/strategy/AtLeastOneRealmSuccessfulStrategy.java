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
import org.apache.shiro.util.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @since 2.0
 */
public class AtLeastOneRealmSuccessfulStrategy implements AuthenticationStrategy {

    public Account execute(AuthenticationAttempt attempt) throws AuthenticationException {

        AuthenticationToken token = attempt.getAuthenticationToken();

        String firstAccountRealmName = null;
        Account firstAccount = null;
        DefaultCompositeAccount compositeAccount = null;

        Map<String, Throwable> realmErrors = new LinkedHashMap<String, Throwable>();

        for (Realm realm : attempt.getRealms()) {

            if (realm.supports(token)) {

                String realmName = realm.getName();

                Account account;
                try {
                    account = realm.authenticateAccount(token);
                } catch (Throwable t) {
                    //noinspection ThrowableResultOfMethodCallIgnored
                    realmErrors.put(realmName, t);
                    continue;
                }

                if (account != null) {
                    if (firstAccount == null) {
                        firstAccount = account;
                        firstAccountRealmName = realmName;
                    } else {
                        if (compositeAccount == null) {
                            compositeAccount = new DefaultCompositeAccount();
                            compositeAccount.appendRealmAccount(firstAccountRealmName, firstAccount);
                        }
                        compositeAccount.appendRealmAccount(realmName, account);
                    }
                }
            }
        }

        if (compositeAccount != null) {
            return compositeAccount;
        }
        if (firstAccount != null) {
            return firstAccount;
        }
        if (!CollectionUtils.isEmpty(realmErrors)) {
            throw new MultiRealmAuthenticationException(realmErrors);
        }

        return null;
    }

}
