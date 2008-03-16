/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authc.credential;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.codec.CodecSupport;

import java.util.Arrays;

/**
 * Simple CredentialsMatcher implementation.  Supports direct (plain) comparison for credentials of type
 * byte[], char[], and Strings, and if the arguments do not match these types, then reverts back to simple
 * <code>Object.equals</code> comparison.
 *
 * <p>Hashing comparisons (the most common technique used in secure applications) are not supported by this class, but
 * instead by {@link HashedCredentialsMatcher HashedCredentialsMatcher} implementations.
 *
 * @see HashedCredentialsMatcher
 * @see Md5CredentialsMatcher
 * @see Sha1CredentialsMatcher
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class SimpleCredentialsMatcher extends CodecSupport implements CredentialsMatcher {

    /**
     * Returns the <tt>token</tt>'s credentials.
     *
     * <p>This default implementation merely returns
     * {@link AuthenticationToken#getCredentials() authenticationToken.getCredentials()} and exists as a template hook
     * if subclasses wish to obtain the credentials in a different way or convert them to a different format before
     * returning.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt.
     * @return the <tt>token</tt>'s associated credentials.
     */
    protected Object getCredentials( AuthenticationToken token ) {
        return token.getCredentials();
    }

    /**
     * Returns the <tt>account</tt>'s credentials.
     *
     * <p>This default implementation merely returns
     * {@link Account#getCredentials() account.getCredentials()} and exists as a template hook if subclasses
     * wish to obtain the credentials in a different way or convert them to a different format before
     * returning.
     *
     * @param account the <tt>Account</tt> stored in the data store to be compared against the submitted authentication
     * token's credentials.
     * @return the <tt>account</tt>'s associated credentials.
     */
    protected Object getCredentials( Account account ) {
        return account.getCredentials();
    }

    /**
     * Returns <tt>true</tt> if the <tt>tokenCredentials</tt> are equal to the <tt>accountCredentials</tt>.
     *
     * <p>This default implementation merely performs an Object equality check,
     * that is <code>accountCredentials.equals(tokenCredentials)</code>.  It primarily exists as a template hook
     * if subclasses wish to determine equality in another way.
     *
     * @param tokenCredentials the <tt>AuthenticationToken</tt>'s associated credentials.
     * @param accountCredentials the <tt>Account</tt>'s stored credentials.
     * @return <tt>true</tt> if the <tt>tokenCredentials</tt> are equal to the <tt>accountCredentials</tt>.
     */
    protected boolean equals( Object tokenCredentials, Object accountCredentials ) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Performing credentials equality check for tokenCredentials of type [" +
            tokenCredentials.getClass().getName() + " and accountCredentials of type [" +
            accountCredentials.getClass().getName() + "]" );
        }
        if ( (tokenCredentials instanceof byte[] || tokenCredentials instanceof char[] || tokenCredentials instanceof String ) &&
             (accountCredentials instanceof byte[] || accountCredentials instanceof char[] || accountCredentials instanceof String ) ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Both credentials arguments can be easily converted to byte arrays.  Performing " +
                        "array equals comparison" );
            }
            byte[] tokenBytes = toBytes(tokenCredentials);
            byte[] accountBytes = toBytes(accountCredentials);
            return Arrays.equals( tokenBytes, accountBytes );
        } else {
            return accountCredentials.equals( tokenCredentials );
        }
    }

    /**
     * Acquires the <tt>token</tt>'s credentials (via {@link #getCredentials(AuthenticationToken) getCredentials(token)})
     * and then the <tt>account</tt>'s credentials
     * (via {@link #getCredentials(Account) getCredentials(account)}) and then passes both of
     * them to the {@link #equals(Object,Object) equals(tokenCredentials, accountCredentials)} method for equality
     * comparison.
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt.
     * @param account the <tt>Account</tt> stored in the system matching the token principal.
     * @return <tt>true</tt> if the provided token credentials are equal to the stored account credentials,
     * <tt>false</tt> otherwise
     */
    public boolean doCredentialsMatch(AuthenticationToken token, Account account) {
        Object tokenCredentials = getCredentials(token);
        Object accountCredentials = getCredentials(account);
        return equals( tokenCredentials, accountCredentials );
    }

}
