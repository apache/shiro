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
import org.apache.shiro.util.Assert;

import java.util.Collection;
import java.util.Collections;

/**
 * @since 2.0
 */
public class DefaultAuthenticationAttempt implements AuthenticationAttempt {

    final AuthenticationToken authenticationToken;
    final Collection<Realm> realms;

    public DefaultAuthenticationAttempt(AuthenticationToken token, Collection<Realm> realms) {
        Assert.notNull(token, "AuthenticationToken cannot be null.");
        Assert.notEmpty(realms, "Realms collection cannot be null or empty.");
        this.authenticationToken = token;
        this.realms = Collections.unmodifiableCollection(realms);
    }

    public AuthenticationToken getAuthenticationToken() {
        return this.authenticationToken;
    }

    public Collection<Realm> getRealms() {
        return this.realms;
    }
}
