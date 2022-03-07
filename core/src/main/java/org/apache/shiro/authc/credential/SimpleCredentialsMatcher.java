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
import org.apache.shiro.lang.codec.CodecSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Arrays;


/**
 * Simple CredentialsMatcher implementation.  Supports direct (plain) comparison for credentials of type
 * byte[], char[], and Strings, and if the arguments do not match these types, then reverts back to simple
 * <code>Object.equals</code> comparison.
 * <p/>
 * <p>Hashing comparisons (the most common technique used in secure applications) are not supported by this class, but
 * instead by the {@link org.apache.shiro.authc.credential.HashedCredentialsMatcher HashedCredentialsMatcher}.
 *
 * @see org.apache.shiro.authc.credential.HashedCredentialsMatcher
 * @since 0.9
 */
public class SimpleCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

    private static final Logger log = LoggerFactory.getLogger(SimpleCredentialsMatcher.class);

    /**
     * Returns the {@code token}'s credentials.
     * <p/>
     * <p>This default implementation merely returns
     * {@link AuthenticationToken#getCredentials() authenticationToken.getCredentials()} and exists as a template hook
     * if subclasses wish to obtain the credentials in a different way or convert them to a different format before
     * returning.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt.
     * @return the {@code token}'s associated credentials.
     */
    protected Object getCredentials(AuthenticationToken token) {
        return token.getCredentials();
    }

    /**
     * Returns the {@code account}'s credentials.
     * <p/>
     * <p>This default implementation merely returns
     * {@link AuthenticationInfo#getCredentials() account.getCredentials()} and exists as a template hook if subclasses
     * wish to obtain the credentials in a different way or convert them to a different format before
     * returning.
     *
     * @param info the {@code AuthenticationInfo} stored in the data store to be compared against the submitted authentication
     *             token's credentials.
     * @return the {@code account}'s associated credentials.
     */
    protected Object getCredentials(AuthenticationInfo info) {
        return info.getCredentials();
    }

    /**
     * Returns {@code true} if the {@code tokenCredentials} argument is logically equal to the
     * {@code accountCredentials} argument.
     * <p/>
     * <p>If both arguments are either a byte array (byte[]), char array (char[]) or String, they will be both be
     * converted to raw byte arrays via the {@link #toBytes toBytes} method first, and then resulting byte arrays
     * are compared via {@link Arrays#equals(byte[], byte[]) Arrays.equals(byte[],byte[])}.</p>
     * <p/>
     * <p>If either argument cannot be converted to a byte array as described, a simple Object <code>equals</code>
     * comparison is made.</p>
     * <p/>
     * <p>Subclasses should override this method for more explicit equality checks.
     *
     * @param tokenCredentials   the {@code AuthenticationToken}'s associated credentials.
     * @param accountCredentials the {@code AuthenticationInfo}'s stored credentials.
     * @return {@code true} if the {@code tokenCredentials} are equal to the {@code accountCredentials}.
     */
    protected boolean equals(Object tokenCredentials, Object accountCredentials) {
        if (log.isDebugEnabled()) {
            log.debug("Performing credentials equality check for tokenCredentials of type [" +
                    tokenCredentials.getClass().getName() + " and accountCredentials of type [" +
                    accountCredentials.getClass().getName() + "]");
        }
        if (isByteSource(tokenCredentials) && isByteSource(accountCredentials)) {
            if (log.isDebugEnabled()) {
                log.debug("Both credentials arguments can be easily converted to byte arrays.  Performing " +
                        "array equals comparison");
            }
            byte[] tokenBytes = toBytes(tokenCredentials);
            byte[] accountBytes = toBytes(accountCredentials);
            return MessageDigest.isEqual(tokenBytes, accountBytes);
        } else {
            return accountCredentials.equals(tokenCredentials);
        }
    }

    /**
     * This implementation acquires the {@code token}'s credentials
     * (via {@link #getCredentials(AuthenticationToken) getCredentials(token)})
     * and then the {@code account}'s credentials
     * (via {@link #getCredentials(org.apache.shiro.authc.AuthenticationInfo) getCredentials(account)}) and then passes both of
     * them to the {@link #equals(Object,Object) equals(tokenCredentials, accountCredentials)} method for equality
     * comparison.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt.
     * @param info  the {@code AuthenticationInfo} stored in the system matching the token principal.
     * @return {@code true} if the provided token credentials are equal to the stored account credentials,
     *         {@code false} otherwise
     */
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenCredentials = getCredentials(token);
        Object accountCredentials = getCredentials(info);
        return equals(tokenCredentials, accountCredentials);
    }

}
