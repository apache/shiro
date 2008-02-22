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
import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Hex;
import org.jsecurity.crypto.hash.AbstractHash;
import org.jsecurity.crypto.hash.Hash;

/**
 * A <tt>HashedCredentialMatcher</tt> provides support for hashing of supplied <tt>AuthenticationToken</tt> credentials
 * before being compared to those in the account from the data store.
 *
 * <p>This class (and its subclasses) function as follows:</p>
 *
 * <p>It first hashes the <tt>AuthenticationToken</tt> credentials supplied by the user during their login.  It then
 * compares this hashed value directly with the account credentials stored in the system.  The stored account
 * credentials are not hashed before the comparison since it is expected that the stored value is already in hashed
 * form.</p>
 *
 * <p>This class is configurable to enable salting the hashed provided credentials as well as performing multiple hash
 * iterations:
 *
 * <p>If you specify that a salt is used, the submitted AuthenticationToken's principals
 * acquired via
 * {@link org.jsecurity.authc.AuthenticationToken#getPrincipal() AuthenticationToken.getPrincipal()} (e.g. a
 * username or user id) will be used to salt the hash.  If you'd like to provide a different salt for an incoming
 * <tt>AuthenticationToken</tt>, you will need to override the
 * {@link #getSalt(AuthenticationToken) getSalt(AuthenticationToken)} to provide the salt a different way.</p>
 *
 * <p>If you hash your users' credentials multiple times before persisting to the data store, you will also need to
 * set this class's {@link #setHashIterations(int) hashIterations} property.</p>
 *
 * <p>The following is some background information and reading on how to properly store user's credentials in a
 * data store:</p>
 *
 * <p>Credential hashing is one of the most common security techniques when safeguarding a user's private credentials
 * (passwords, keys, etc).  Most developers never want to store their users' credentials in plain form, viewable by
 * anyone, so they often hash the users' credentials before they are saved in the data store.</p>
 *
 * <p>But, simple hashing by itself is often not good enough.  Many times, you will want to salt the hash and
 * potentially re-hash the value multiple times.  The reasons why are beyond the scope of this JavaDoc, but there is a
 * decent <a href="http://www.owasp.org/index.php/Hashing_Java" _target="blank">Hashing Java article</a> that explains 
 * what a 'salt' is and why multiple hash iterations are useful.</p>
 *
 * <p>Make note of sections 5 &quot;Why add salt?&quot; and 6 "Hardening against the attacker's attack".</p>
 *
 * <p>This class effectively supports comparisons of credentials that were hashed using the above mentioned hashing,
 * salting, and iterations techniques.</p>
 *
 * <p>Note that all of JSecurity's Hash implementations (for example,
 * {@link org.jsecurity.crypto.hash.Md5Hash Md5Hash}, {@link org.jsecurity.crypto.hash.ShaHash ShaHash}, etc)
 * support salting and multiple hash iterations via overloaded constructors.
 *
 * @see org.jsecurity.crypto.hash.Md5Hash
 * @see org.jsecurity.crypto.hash.ShaHash
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class HashedCredentialsMatcher extends SimpleCredentialsMatcher {

    private boolean storedCredentialsHexEncoded = true; //false means base64 encoded
    private boolean hashSalted = false;
    private int hashIterations = 1;

    /**
     * Returns <tt>true</tt> if the system's stored credential hash is Hex encoded, <tt>false</tt> if it
     * is Base64 encoded.
     *
     * <p>Default value unless overridden with the corresponding setter method is <tt>true</tt></p>
     *
     * @return <tt>true</tt> if the system's stored credential hash is Hex encoded, <tt>false</tt> if it
     *         is Base64 encoded.  Default is <tt>true</tt>
     */
    public boolean isStoredCredentialsHexEncoded() {
        return storedCredentialsHexEncoded;
    }

    /**
     * Sets the indicator if this system's stored credential hash is Hex encoded or not.
     *
     * <p>A value of <tt>true</tt> will cause this class to decode the system credential from Hex, a
     * value of <tt>false</tt> will cause this class to decode the system credential from Base64.</p>
     *
     * <p>Unless overridden via this method, the default value is <tt>true</tt>.
     *
     * @param storedCredentialsHexEncoded the indicator if this system's stored credential hash is Hex
     *                                    encoded or not ('not' automatically implying it is Base64 encoded).
     */
    public void setStoredCredentialsHexEncoded(boolean storedCredentialsHexEncoded) {
        this.storedCredentialsHexEncoded = storedCredentialsHexEncoded;
    }

    public boolean isHashSalted() {
        return hashSalted;
    }

    public void setHashSalted(boolean hashSalted) {
        this.hashSalted = hashSalted;
    }

    public int getHashIterations() {
        return hashIterations;
    }

    public void setHashIterations(int hashIterations) {
        this.hashIterations = hashIterations;
    }

    protected Object getSalt( AuthenticationToken token ) {
        return token.getPrincipal();
    }

    protected Object getCredentials(AuthenticationToken token) {
        Object salt = isHashSalted() ? getSalt( token ) : null;
        return getProvidedCredentialsHash(token.getCredentials(), salt, getHashIterations() );
    }

    protected Object getCredentials(Account account) {
        Object credentials = account.getCredentials();

        //assume stored credential is already hashed:
        AbstractHash hash = newHashInstance();

        //apply stored credentials to this Hash instance
        byte[] storedBytes = toBytes(credentials);

        if (!(credentials instanceof byte[])) {
            //method argument came in as a char[] or String, so
            //we need to do text decoding first:
            if (isStoredCredentialsHexEncoded()) {
                storedBytes = Hex.decode( storedBytes );
            } else {
                storedBytes = Base64.decodeBase64( storedBytes );
            }
        }
        hash.setBytes( storedBytes );
        return hash;
    }

    protected abstract Hash getProvidedCredentialsHash(Object credential, Object salt, int hashIterations );

    /**
     * Returns a new, <em>uninitialized</em> instance, without its byte array set.
     *
     * @return a new, <em>uninitialized</em> instance, without its byte array set.
     */
    protected abstract AbstractHash newHashInstance();

}
