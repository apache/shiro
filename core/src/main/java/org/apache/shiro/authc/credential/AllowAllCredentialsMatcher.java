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
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * A credentials matcher that always returns {@code true} when matching credentials no matter what arguments
 * are passed in.  This can be used for testing or when credentials are implicitly trusted for a particular
 * {@link org.apache.shiro.realm.Realm Realm}.
 *
 * @since 0.2
 */
public class AllowAllCredentialsMatcher implements CredentialsMatcher {

    /**
     * Returns <code>true</code> <em>always</em> no matter what the method arguments are.
     *
     * @param token   the token submitted for authentication.
     * @param info    the account being verified for access
     * @return <code>true</code> <em>always</em>.
     */
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        return true;
    }
}
