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

import org.apache.shiro.util.ByteSource;

/**
 * A {@code PasswordService} supports common use cases when using passwords as a credentials mechanism.
 * <p/>
 * Most importantly, implementations of this interface are expected to employ best-practices to ensure that
 * passwords remain as safe as possible in application environments.
 * <h2>Usage</h2>
 * A {@code PasswordService} is used at two different times during an application's lifecycle:
 * <ul>
 * <li>When creating a user account or resetting their password</li>
 * <li>When a user logs in, when passwords must be compared</li>
 * </ul>
 * <h3>Account Creation or Password Reset</h3>
 * Whenever you create a new user account or reset that account's password, we must translate the end-user submitted
 * raw/plaintext password value to a string format that is much safer to store.  You do that by calling the
 * {@link #hashPassword(ByteSource)} method to create the safer hashed and formatted value.  For
 * example:
 * <pre>
 * ByteSource plaintextBytes = ByteSource.Util.bytes(submittedPlaintextPassword);
 * String hashed = passwordService.hashPassword(plaintextBytes);
 * ...
 * userAccount.setHashedPassword(hashed);
 * userAccount.save(); //create or update to your data store
 * </pre>
 * Be sure to save this hashed password in your data store and never the original/raw submitted password.
 * <h3>Login Password Comparison</h3>
 * Shiro performs the comparison during login automatically.  Along with your {@code PasswordService}, you just
 * have to configure a {@link PasswordMatcher} on a realm that has password-based accounts.   During a login attempt,
 * shiro will use the {@code PasswordMatcher} and the {@code PasswordService} to automatically compare submitted
 * passwords.
 * <p/>
 * For example, if using Shiro's INI, here is how you might configure the PasswordMatcher and PasswordService:
 * <pre>
 * [main]
 * ...
 * passwordService = org.apache.shiro.authc.credential.DefaultPasswordService
 * # configure the passwordService to use the hashing settings you desire
 * ...
 * passwordMatcher = org.apache.shiro.authc.credential.PasswordMatcher
 * passwordMatcher.passwordService = $passwordService
 * ...
 * # Finally, set the matcher on a realm that requires password matching for account authentication:
 * myRealm = ...
 * myRealm.credentialsMatcher = $passwordMatcher
 * </pre>
 *
 * @see DefaultPasswordService
 * @see PasswordMatcher
 * @since 1.2
 */
public interface PasswordService {

    /**
     * Hashes the specified plaintext password (usually acquired from your application's 'new user' or 'password reset'
     * workflow).  After this call returns, you typically will store the returned formatted String with the
     * corresponding user record (e.g. as the 'password' or 'passwordHash' attribute).
     * <p/>
     * The String returned from this argument must be presented to the
     * {@link #passwordsMatch(ByteSource, String) passwordsMatch} method when performing a
     * password comparison check.
     * <h3>Usage</h3>
     * The input argument type is a {@code ByteSource} to support either String or character array
     * {@code (char[])} arguments; character arrays are often a safer way to represent passwords as they can be
     * cleared/nulled-out after use.
     * <p/>
     * Regardless of your choice of using Strings or character arrays to represent submitted passwords, you can wrap
     * either as a {@code ByteSource} by using {@link ByteSource.Util}, for example, when the passwords are captured as
     * Strings:
     * <pre>
     * ByteSource passwordBytes = ByteSource.Util.bytes(submittedPasswordString);
     * String formattedHashedValue = passwordService.hashPassword(passwordBytes);
     * </pre>
     * or, identically, when captured as a character array:
     * <pre>
     * ByteSource passwordBytes = ByteSource.Util.bytes(submittedPasswordCharacterArray);
     * String formattedHashedValue = passwordService.hashPassword(passwordBytes);
     * </pre>
     * <p/>
     * The resulting {@code formattedHashedValue} should be stored with the account to be retrieved later during a
     * login attempt.  For example:
     * <pre>
     * String formattedHashedValue = passwordService.hashPassword(passwordBytes);
     * ...
     * userAccount.setHashedPassword(formattedHashedValue);
     * userAccount.save(); //create or update to your data store
     * </pre>
     *
     * @param plaintext a {@code ByteSource} encapsulating a plaintext password's bytes, usually acquired from your
     *                  application's 'new user' or 'password reset' workflow.
     * @return the hashed password, formatted for storage.
     */
    String hashPassword(ByteSource plaintext);

    /**
     * Returns {@code true} if the {@code submittedPlaintext} password matches the existing {@code saved} password,
     * {@code false} otherwise.
     * <h3>Usage</h3>
     * The {@code submittedPlaintext} argument is a {@code ByteSource} to support both String and character array
     * arguments.  Regardless of which you use to capture submitted passwords, you can wrap either as a
     * {@code ByteSource} as follows:
     * <pre>
     * ByteSource submittedPasswordBytes = ByteSource.Util.bytes(submittedPasswordStringOrCharacterArray);
     * passwordService.passwordsMatch(submittedPasswordBytes, formattedHashedPassword);
     * </pre>
     *
     * @param submittedPlaintext a raw/plaintext password submitted by an end user/Subject.
     * @param saved              the previously hashed and formatted password known to be associated with an account.
     *                           This value must have been previously generated from the
     *                           {@link #hashPassword(ByteSource) hashPassword} method (typically
     *                           when the account is created or the account's password is reset).
     * @return {@code true} if the {@code submittedPlaintext} password matches the existing {@code saved} password,
     *         {@code false} otherwise.
     */
    boolean passwordsMatch(ByteSource submittedPlaintext, String saved);
}
