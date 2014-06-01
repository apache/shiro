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
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.CollectionUtils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The {@code FirstRealmSuccessfulStrategy} will iterate over the available realms and invoke
 * {@code realm.}{@link Realm#authenticateAccount(org.apache.shiro.authc.AuthenticationToken) authenticateAccount(authenticationToken)}
 * on each one; the first time a realm returns an {@code Account} without throwing an exception, that
 * account is returned immediately, and all subsequent realms are ignored entirely (iteration 'short circuits').
 * <p/>
 * If no realms return an {@code Account}:
 * <ul>
 *     <li>If only one exception was thrown by any consulted Realm, that exception is thrown.</li>
 *     <li>If more than one Realm threw an exception during consultation, those exceptions are bundled together as a
 *         {@link MultiRealmAuthenticationException} and that exception is thrown.</li>
 *     <li>If no exceptions were thrown, {@code null} is returned, indicating to the calling
 *         {@link org.apache.shiro.authc.Authenticator Authenticator} that no account could be found.</li>
 * </ul>
 *
 * @since 2.0
 */
public class FirstRealmSuccessfulStrategy implements AuthenticationStrategy {

    public Account execute(AuthenticationAttempt attempt) throws AuthenticationException {

        AuthenticationToken token = attempt.getAuthenticationToken();

        Map<String, Throwable> realmErrors = new LinkedHashMap<String, Throwable>();

        for(Realm realm : attempt.getRealms()) {

            if (realm.supports(token)) {

                Account account;

                try {
                    account = realm.authenticateAccount(token);
                } catch (Throwable t) {

                    //noinspection ThrowableResultOfMethodCallIgnored
                    realmErrors.put(realm.getName(), t);

                    //current realm failed - try the next one:
                    continue;
                }

                if (account != null) {
                    //successfully acquired an account - stop iterating, return immediately:
                    return account;
                }
            }
        }

        if (!CollectionUtils.isEmpty(realmErrors)) {
            if (realmErrors.size() == 1) {
                Throwable t = realmErrors.values().iterator().next();
                if (t instanceof AuthenticationException) {
                    throw (AuthenticationException)t;
                }
                throw new AuthenticationException("Unable to authenticate realm account.", t);
            } //else more than one throwable encountered:
            throw new MultiRealmAuthenticationException(realmErrors);
        }

        return null;
    }
}
