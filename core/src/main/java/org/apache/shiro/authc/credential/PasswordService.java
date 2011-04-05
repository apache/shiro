/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc.credential;

import org.apache.shiro.crypto.hash.HashResponse;
import org.apache.shiro.util.ByteSource;

/**
 * A {@code PasswordService} supports common use cases when using passwords as a credentials mechanism.
 * <p/>
 * Most importantly, implementations of this interface are expected to employ best-practices to ensure that
 * passwords remain as safe as possible in application environments.
 * <p/>
 * As this interface extends the CredentialsMatcher interface, it will perform credentials matching for password-based
 * authentication attempts.  However, this interface includes another additional method,
 * {@link #hashPassword(org.apache.shiro.util.ByteSource)} which will hash a raw password value into a more
 * secure hashed format.
 * <h2>Usage</h2>
 * To use this service effectively, you must do the following:
 * <p/>
 * <ol>
 * <li>Define an implementation of this interface in your Shiro configuration.  For example, in {@code shiro.ini}:
 * <pre>
 * [main]
 * ...
 * passwordService = org.apache.shiro.authc.credential.DefaultPasswordService
 * </pre>
 * </li>
 * <li>Configure the {@code passwordService} instance with the most secure settings based on your application's needs.
 * See the {@link DefaultPasswordService DefaultPasswordService JavaDoc} for configuration options.  For example:
 * <pre>
 * ...
 * passwordService.hasher.baseSalt = _some_random_base64_encoded_byte_array_
 * passwordService.hasher.hashIterations = 250000
 * ...
 * </pre>
 * </li>
 * <li>Wire the password service into the {@code Realm} that will query for password-based accounts.  The realm
 * implementation is usually a subclass of {@link org.apache.shiro.realm.AuthenticatingRealm AuthenticatingRealm}, which
 * supports configuration of a {@link CredentialsMatcher} instance:
 * <pre>
 * ...
 * myRealm.credentialsMatcher = $passwordService
 * ...
 * </pre>
 * </li>
 * <li>During your application's new-user or password-reset workflow (whenever a user submits to you a new plaintext
 * password), call the {@link #hashPassword(org.apache.shiro.util.ByteSource)} method immediately to acquire the
 * hashed version.  Store the returned {@link org.apache.shiro.crypto.hash.HashResponse#getHash() hash} and
 * {@link org.apache.shiro.crypto.hash.HashResponse#getSalt() salt} instance to your user data store (and <em>NOT</em>
 * the original raw password).</li>
 * <li>Ensure your corresponding Realm implementation (that was configured with the {@code PasswordService} as its
 * credentialsMatcher above) returns instances of
 * {@link org.apache.shiro.authc.SaltedAuthenticationInfo SaltedAuthenticationInfo} during authentication attempts
 * (typically represented by a call to your realm's
 * {@link org.apache.shiro.realm.AuthenticatingRealm#doGetAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken) doGetAuthenticationInfo}
 * method).  Ensure the {@code SaltedAuthenticationInfo} instance you construct returns the saved hash and salt you
 * saved from step #4.</li>
 * </ol>
 * If you perform these steps and configure the {@code PasswordService) appropriately, you can rest assured you will be
 * using very strong password hashing techniques.
 *
 * @since 1.2
 */
public interface PasswordService extends CredentialsMatcher {

    /**
     * Hashes the specified plain text password (usually acquired from your application's 'new user' or 'password reset'
     * workflow).  After this call returns, you typically will store the returned
     * response's {@link org.apache.shiro.crypto.hash.HashResponse#getHash() hash} and
     * {@link org.apache.shiro.crypto.hash.HashResponse#getSalt() salt} with the corresponding user record (e.g.
     * in a database).
     *
     * @param plaintextPassword a plain text password, usually acquired from your application's 'new user' or 'password reset'
     *                          workflow.
     * @return the password hash and salt to be stored with the corresponding user record.
     */
    HashResponse hashPassword(ByteSource plaintextPassword);


}
