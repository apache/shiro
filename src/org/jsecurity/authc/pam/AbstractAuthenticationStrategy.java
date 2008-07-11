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
import org.jsecurity.authc.SimpleAccount;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.realm.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractAuthenticationStrategy implements ModularAuthenticationStrategy {

    protected transient final Logger log = LoggerFactory.getLogger(getClass());

    public Account beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException {
        return new SimpleAuthorizingAccount();
    }

    public Account beforeAttempt(Realm realm, AuthenticationToken token, Account aggregate) throws AuthenticationException {
        return aggregate;
    }

    public Account afterAttempt(Realm realm, AuthenticationToken token, Account singleRealmAccount, Account aggregateAccount, Throwable t) throws AuthenticationException {
        Account account;
        if (singleRealmAccount == null) {
            account = aggregateAccount;
        } else {
            if (aggregateAccount == null) {
                account = singleRealmAccount;
            } else {
                account = merge(singleRealmAccount, aggregateAccount);
            }
        }

        return account;
    }

    protected Account merge(Account singleRealmAccount, Account aggregateAccount) {
        if (aggregateAccount instanceof SimpleAccount) {
            ((SimpleAccount) aggregateAccount).merge(singleRealmAccount);
            return aggregateAccount;
        } else {
            return singleRealmAccount;
        }
    }

    public Account afterAllAttempts(AuthenticationToken token, Account aggregate) throws AuthenticationException {
        return aggregate;
    }
}
