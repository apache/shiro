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
package org.jsecurity.authc.event.mgt;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.subject.PrincipalCollection;

/**
 * An AuthenticationEventFactory functions as its name implies - a Factory design pattern
 * implementation that generates AuthenticationEvents.  After created, these events can then be
 * sent to interested {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public interface AuthenticationEventFactory {

    /**
     * Creates an AuthenticationEvent after a failed authentication attempt.
     *
     * @param token - the authentication token submitted during the authentication attempt.
     * @param ex    - the exception thrown during the attempt.
     * @return the AuthenticationEvent to send due to the failed attempt.
     * @see org.jsecurity.authc.event.SuccessfulAuthenticationEvent
     */
    AuthenticationEvent createFailureEvent(AuthenticationToken token, AuthenticationException ex);

    /**
     * Creates an AuthenticationEvent after a successful authentication (log-in).
     *
     * @param token   the authentication token submitted during the authentication attempt.
     * @param account the account data retrieved in response to the successful token submission.
     * @return the AuthenticationEvent to send due to the successful log-in attempt.
     * @see org.jsecurity.authc.event.FailedAuthenticationEvent
     */
    AuthenticationEvent createSuccessEvent(AuthenticationToken token, Account account);

    /**
     * Creates an AuthenticationEvent in response to a Subject logging out.
     *
     * @param principals the application-specific Subject/account identifier(s).
     * @return an AuthenticationEvent to send due to the Subject logging out.
     * @see org.jsecurity.authc.event.LogoutEvent
     */
    AuthenticationEvent createLogoutEvent(PrincipalCollection principals);
}
