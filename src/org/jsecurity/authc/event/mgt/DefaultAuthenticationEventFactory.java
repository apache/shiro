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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.FailedAuthenticationEvent;
import org.jsecurity.authc.event.LogoutEvent;
import org.jsecurity.authc.event.SuccessfulAuthenticationEvent;
import org.jsecurity.subject.PrincipalCollection;

/**
 * Simple principal-based implementation of the AuthenticationEventFactory interface.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class DefaultAuthenticationEventFactory implements AuthenticationEventFactory {

    /**
     * Uses the principal found in the token to construct a {@link org.jsecurity.authc.event.FailedAuthenticationEvent}
     *
     * @param token the authentication token submitted during the authentication attempt
     * @param cause the cause of the failed authentication attempt
     * @return a {@link org.jsecurity.authc.event.FailedAuthenticationEvent} to send due to the failed attempt.
     */
    public AuthenticationEvent createFailureEvent(AuthenticationToken token, AuthenticationException cause) {
        return new FailedAuthenticationEvent(token, cause);
    }

    /**
     * Uses the principal found in the <em>AuthenticationInfo</em> parameter (not the authentication token) to
     * construct a {@link org.jsecurity.authc.event.SuccessfulAuthenticationEvent}
     *
     * @param token   the authentication token submitted during the authentication attempt.
     * @param info
     * @return a {@link org.jsecurity.authc.event.SuccessfulAuthenticationEvent} to send due to the successful attempt.
     */
    public AuthenticationEvent createSuccessEvent(AuthenticationToken token, AuthenticationInfo info) {
        return new SuccessfulAuthenticationEvent(token, info);
    }

    public AuthenticationEvent createLogoutEvent(PrincipalCollection principals) {
        return new LogoutEvent(principals);
    }
}
