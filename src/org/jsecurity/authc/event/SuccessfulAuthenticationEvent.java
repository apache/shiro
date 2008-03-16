/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authc.event;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;

/**
 * Event triggered when an authentication attempt is successful.
 * 
 * <p>The {@link Account Account} object returned after the successful authentication is available via the
 * {@link #getAccount() getAccount()} method.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SuccessfulAuthenticationEvent extends AttemptedAuthenticationEvent {

    private Account account = null;

    public SuccessfulAuthenticationEvent( AuthenticationToken token, Account account ) {
        this( token, account, null );
    }

    public SuccessfulAuthenticationEvent( AuthenticationToken token, Account account, Object source ) {
        super( token, source );
        this.account = account;
    }

    public Account getAccount() {
        return this.account;
    }

}
