/*
* Copyright (C) 2005-2008 Les Hazlewood
*
* This library is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published
* by the Free Software Foundation; either version 2.1 of the License, or
* (at your option) any later version.
*
* This library is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
* or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
* Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this library; if not, write to the
*
* Free Software Foundation, Inc.
* 59 Temple Place, Suite 330
* Boston, MA 02111-1307
* USA
*
* Or, you may view it online at
* http://www.opensource.org/licenses/lgpl-license.php
*/
package org.jsecurity.authc.credential;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.SimpleAccount;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.codec.CodecSupport;

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
 * @see ShaCredentialsMatcher
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
        return accountCredentials.equals(tokenCredentials);
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
        Object tokenCredentials = getCredentials( token );
        Object accountCredentials = getCredentials( account );
        return equals( tokenCredentials, accountCredentials );
    }

    /**
     * Simple method to test the equality-checking logic.
     * @param args command line arguments (ignored).
     */
    public static void main( String[] args ) {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        AuthenticationToken token = new UsernamePasswordToken( "user1", "blah" );
        Account account = new SimpleAccount( "user1", toBytes("blah") );
        boolean matches = matcher.doCredentialsMatch(token, account);
        System.out.println("Principals match? " + matches );
    }


}
