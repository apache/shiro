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
package org.apache.shiro.authc;

import org.apache.shiro.subject.PrincipalCollection;

/**
 * An {@code AuthenticationListener} listens for notifications while {@code Subject}s authenticate with the system.
 *
 * @since 0.9
 */
public interface AuthenticationListener {

    /**
     * Callback triggered when an authentication attempt for a {@code Subject} has succeeded.
     *
     * @param token the authentication token submitted during the {@code Subject} (user)'s authentication attempt.
     * @param info  the authentication-related account data acquired after authentication for the corresponding {@code Subject}.
     */
    void onSuccess(AuthenticationToken token, AuthenticationInfo info);

    /**
     * Callback triggered when an authentication attempt for a {@code Subject} has failed.
     *
     * @param token the authentication token submitted during the {@code Subject} (user)'s authentication attempt.
     * @param ae    the {@code AuthenticationException} that occurred as a result of the attempt.
     */
    void onFailure(AuthenticationToken token, AuthenticationException ae);

    /**
     * Callback triggered when a {@code Subject} logs-out of the system.
     * <p/>
     * This method will only be triggered when a Subject explicitly logs-out of the session.  It will not
     * be triggered if their Session times out.
     *
     * @param principals the identifying principals of the Subject logging out.
     */
    void onLogout(PrincipalCollection principals);
}
