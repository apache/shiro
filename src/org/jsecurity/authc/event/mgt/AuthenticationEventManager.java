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
import org.jsecurity.subject.PrincipalCollection;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationEventManager extends AuthenticationEventFactory, AuthenticationEventSender {

    /**
     * Utility method that first creates a failure event based on the given token and exception and then actually sends
     * the event.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param ae    the <tt>AuthenticationException</tt> that occurred as a result of the attempt.
     */
    void sendFailureEvent(AuthenticationToken token, AuthenticationException ae);

    /**
     * Utility method that first creates a success event based on the given token and account and then actually sends
     * the event.
     *
     * @param token   the authentication token reprenting the subject (user)'s authentication attempt.
     * @param info
     */
    void sendSuccessEvent(AuthenticationToken token, AuthenticationInfo info);

    /**
     * Utility method that first creates a logout event based on the given subjectIdentifier and then actually
     * sends the event.
     *
     * @param subjectPrincipal the application-specific Subject/user identifier.
     */
    void sendLogoutEvent(PrincipalCollection subjectPrincipal);
}
