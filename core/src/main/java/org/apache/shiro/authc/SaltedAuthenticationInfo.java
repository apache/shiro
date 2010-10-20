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

import org.apache.shiro.util.ByteSource;

/**
 * Interface representing account information that may use a salt when hashing credentials.  This interface
 * exists primarily to support environments that hash user credentials (e.g. passwords).
 * <p/>
 * Salts should typically be generated from a secure pseudo-random number generator so they are effectively
 * impossible to guess.  The salt value should be safely stored along side the account information to ensure
 * it is maintained along with the account's credentials.
 * <p/>
 * This interface exists as a way for Shiro to acquire that salt so it can correctly perform
 * {@link org.apache.shiro.authc.credential.CredentialsMatcher credentials matching} during login attempts.
 * See the {@link org.apache.shiro.authc.credential.HashedCredentialsMatcher HashedCredentialsMatcher} JavaDoc for
 * more information on hashing credentials with salts.
 *
 * @see org.apache.shiro.authc.credential.HashedCredentialsMatcher
 *
 * @since 1.1
 */
public interface SaltedAuthenticationInfo extends AuthenticationInfo {

    /**
     * Returns the salt used to salt the account's credentials or {@code null} if no salt was used.
     *
     * @return the salt used to salt the account's credentials or {@code null} if no salt was used.
     */
    ByteSource getCredentialsSalt();
}
