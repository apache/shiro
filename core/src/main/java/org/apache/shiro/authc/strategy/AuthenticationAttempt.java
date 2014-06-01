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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;

import java.util.Collection;

/**
 * An {@code AuthenticationAttempt} encapsulates all information required for an
 * {@link AuthenticationStrategy} to perform a multi-realm authentication submission.
 *
 * @see DefaultAuthenticationAttempt
 * @since 2.0
 */
public interface AuthenticationAttempt {

    /**
     * Returns the submitted authentication token for which an authenticated account may be returned.
     *
     * @return the submitted authentication token for which an authenticated account may be returned.
     */
    AuthenticationToken getAuthenticationToken();

    /**
     * Returns the realms to consult to authenticate the associated {@link #getAuthenticationToken() authenticationToken}.
     *
     * @return the realms to consult to authenticate the associated {@link #getAuthenticationToken() authenticationToken}.
     */
    Collection<Realm> getRealms();
}
