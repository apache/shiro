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

import org.apache.shiro.lang.util.ByteSource;

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
 * {@link #encryptPassword(Object)} method to create the safer value.  For
 * example:
 * <pre>
 * String submittedPlaintextPassword = ...
 * String encryptedValue = passwordService.encryptPassword(submittedPlaintextPassword);
 * ...
 * userAccount.setPassword(encryptedValue);
 * userAccount.save(); //create or update to your data store
 * </pre>
 * Be sure to save this encrypted password in your data store and never the original/raw submitted password.
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
 * # configure the passwordService to use the settings you desire
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
     * Converts the specified plaintext password (usually acquired from your application's 'new user' or 'password reset'
     * workflow) into a formatted string safe for storage.  The returned string can be safely saved with the
     * corresponding user account record (e.g. as a 'password' attribute).
     * <p/>
     * It is expected that the String returned from this method will be presented to the
     * {@link #passwordsMatch(Object, String) passwordsMatch(plaintext,encrypted)} method when performing a
     * password comparison check.
     * <h3>Usage</h3>
     * The input argument type can be any 'byte backed' {@code Object} - almost always either a
     * String or character array representing passwords (character arrays are often a safer way to represent passwords
     * as they can be cleared/nulled-out after use.  Any argument type supported by
     * {@link ByteSource.Util#isCompatible(Object)} is valid.
     * <p/>
     * For example:
     * <pre>
     * String rawPassword = ...
     * String encryptedValue = passwordService.encryptPassword(rawPassword);
     * </pre>
     * or, identically:
     * <pre>
     * char[] rawPasswordChars = ...
     * String encryptedValue = passwordService.encryptPassword(rawPasswordChars);
     * </pre>
     * <p/>
     * The resulting {@code encryptedValue} should be stored with the account to be retrieved later during a
     * login attempt.  For example:
     * <pre>
     * String encryptedValue = passwordService.encryptPassword(rawPassword);
     * ...
     * userAccount.setPassword(encryptedValue);
     * userAccount.save(); //create or update to your data store
     * </pre>
     *
     * @param plaintextPassword the raw password as 'byte-backed' object (String, character array, {@link ByteSource},
     *                          etc) usually acquired from your application's 'new user' or 'password reset' workflow.
     * @return the encrypted password, formatted for storage.
     * @throws IllegalArgumentException if the argument cannot be easily converted to bytes as defined by
     *                                  {@link ByteSource.Util#isCompatible(Object)}.
     * @see ByteSource.Util#isCompatible(Object)
     */
    String encryptPassword(Object plaintextPassword) throws IllegalArgumentException;

    /**
     * Returns {@code true} if the {@code submittedPlaintext} password matches the existing {@code saved} password,
     * {@code false} otherwise.
     * <h3>Usage</h3>
     * The {@code submittedPlaintext} argument type can be any 'byte backed' {@code Object} - almost always either a
     * String or character array representing passwords (character arrays are often a safer way to represent passwords
     * as they can be cleared/nulled-out after use.  Any argument type supported by
     * {@link ByteSource.Util#isCompatible(Object)} is valid.
     * <p/>
     * For example:
     * <pre>
     * String submittedPassword = ...
     * passwordService.passwordsMatch(submittedPassword, encryptedPassword);
     * </pre>
     * or similarly:
     * <pre>
     * char[] submittedPasswordCharacters = ...
     * passwordService.passwordsMatch(submittedPasswordCharacters, encryptedPassword);
     * </pre>
     *
     * @param submittedPlaintext a raw/plaintext password submitted by an end user/Subject.
     * @param encrypted          the previously encrypted password known to be associated with an account.
     *                           This value is expected to have been previously generated from the
     *                           {@link #encryptPassword(Object) encryptPassword} method (typically
     *                           when the account is created or the account's password is reset).
     * @return {@code true} if the {@code submittedPlaintext} password matches the existing {@code saved} password,
     *         {@code false} otherwise.
     * @see ByteSource.Util#isCompatible(Object)
     */
    boolean passwordsMatch(Object submittedPlaintext, String encrypted);
}
