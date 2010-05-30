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

import org.apache.shiro.crypto.hash.AbstractHash;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.Sha512Hash;


/**
 * <tt>HashedCredentialsMatcher</tt> implementation that expects the stored <tt>AuthenticationInfo</tt> credentials to be
 * SHA-512 hashed.
 *
 * @since 0.9
 */
public class Sha512CredentialsMatcher extends HashedCredentialsMatcher {

    /**
     * Creates a new <em>uninitialized</em> {@link Sha512Hash Sha512Hash} instance, without it's byte array set.
     *
     * @return a new <em>uninitialized</em> {@link org.apache.shiro.crypto.hash.Sha512Hash Sha512Hash} instance, without it's byte array set.
     */
    protected AbstractHash newHashInstance() {
        return new Sha512Hash();
    }

    /**
     * This implementation merely returns
     * <code>new {@link Sha512Hash#Sha512Hash(Object, Object, int) Sha512Hash(credentials,salt,hashIterations)}</code>.
     */
    protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
        return new Sha512Hash(credentials, salt, hashIterations);
    }
}
