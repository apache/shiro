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
package org.jsecurity.authc;

import org.jsecurity.subject.PrincipalCollection;

/**
 * An <code>AuthenticationListener</code> is notified of noteworthy events while
 * {@link org.jsecurity.subject.Subject Subject}s authenticate with the system.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationListener {

    /**
     * Callback triggered when an authentication attempt for a <code>Subject</code> has succeeded.
     *
     * @param token the authentication token submitted during the <code>Subject</code> (user)'s authentication attempt.
     * @param info  the authentication-related account data acquired after authentication for the corresponding <code>Subject</code>.
     */
    void onSuccess(AuthenticationToken token, AuthenticationInfo info);

    /**
     * Callback triggered when an authentication attempt for a <code>Subject</code> has failed.
     *
     * @param token the authentication token submitted during the <code>Subject</code> (user)'s authentication attempt.
     * @param ae    the <tt>AuthenticationException</tt> that occurred as a result of the attempt.
     */
    void onFailure(AuthenticationToken token, AuthenticationException ae);

    /**
     * Callback triggered when a <code>Subject</code> logs out of the system.
     *
     * @param principals the identifying principals of the Subject logging out.
     */
    void onLogout(PrincipalCollection principals);
}
