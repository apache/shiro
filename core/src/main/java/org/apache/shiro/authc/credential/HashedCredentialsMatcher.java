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
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.hash.AbstractHash;
import org.apache.shiro.crypto.hash.Hash;

/**
 * A {@code HashedCredentialMatcher} provides support for hashing of supplied {@code AuthenticationToken} credentials
 * before being compared to those in the {@code AuthenticationInfo} from the data store.
 * <p/>
 * Credential hashing is one of the most common security techniques when safeguarding a user's private credentials
 * (passwords, keys, etc).  Most developers never want to store their users' credentials in plain form, viewable by
 * anyone, so they often hash the users' credentials before they are saved in the data store.
 * <p/>
 * This class (and its subclasses) function as follows:
 * <p/>
 * It first hashes the {@code AuthenticationToken} credentials supplied by the user during their login.  It then
 * compares this hashed value directly with the {@code AuthenticationInfo} credentials stored in the system.  The stored account
 * credentials are expected to already be in hashed form.  If these two values are equal, the submitted credentials
 * match.
 * <h3>Salting and Multiple Hash Iterations</h3>
 * Because simple hashing is sometimes not good enough for many applications, this class also supports 'salting'
 * and multiple hash iterations.  Please read this excellent
 * <a href="http://www.owasp.org/index.php/Hashing_Java" _target="blank">Hashing Java article</a> to learn about
 * salting and multiple iterations and why you might want to use them. (Note of sections 5
 * &quot;Why add salt?&quot; and 6 "Hardening against the attacker's attack").
 * <p/>
 * We should also note here that all of Shiro's Hash implementations (for example,
 * {@link org.apache.shiro.crypto.hash.Md5Hash Md5Hash}, {@link org.apache.shiro.crypto.hash.Sha1Hash Sha1Hash}, etc)
 * support salting and multiple hash iterations via overloaded constructors.
 * <h4>Salting</h4>
 * Salting of the authentication token's credentials hash is disabled by default, but you may enable it by setting
 * {@link #setHashSalted hashSalted} to
 * {@code true}.  If you do enable it, the value used to salt the hash will be
 * obtained from {@link #getSalt(org.apache.shiro.authc.AuthenticationToken) getSalt(authenticationToken)}.
 * <p/>
 * The default {@code getSalt} implementation merely returns
 * {@code token.getPrincipal()}, effectively using the user's identity as the salt, a most common
 * technique.  If you wish to provide the authentication token's salt another way, you may override this
 * {@code getSalt} method.
 * <h4>Multiple Hash Iterations</h4>
 * If you hash your users' credentials multiple times before persisting to the data store, you will also need to
 * set this class's {@link #setHashIterations(int) hashIterations} property.
 * <p/>
 * <b>Note:</b> <a href="http://en.wikipedia.org/wiki/MD5">MD5</a> and
 * <a href="http://en.wikipedia.org/wiki/SHA_hash_functions">SHA-1</a> algorithms are now known to be vulnerable to
 * compromise and/or collisions (read the linked pages for more).  While most applications are ok with either of these
 * two, if your application mandates high security, use the SHA-256 (or higher) hashing algorithms and their
 * supporting {@code CredentialsMatcher} implementations.
 *
 * @author Les Hazlewood
 * @see org.apache.shiro.crypto.hash.Md5Hash
 * @see org.apache.shiro.crypto.hash.Sha1Hash
 * @see org.apache.shiro.crypto.hash.Sha256Hash
 * @since 0.9
 */
public abstract class HashedCredentialsMatcher extends SimpleCredentialsMatcher {

    private boolean storedCredentialsHexEncoded = true; //false means base64 encoded
    private boolean hashSalted = false;
    private int hashIterations = 1;

    /**
     * Returns {@code true} if the system's stored credential hash is Hex encoded, {@code false} if it
     * is Base64 encoded.
     * <p/>
     * Default value is {@code true} for convenience - all of Shiro's {@link Hash Hash#toString()}
     * implementations return Hex encoded values by default, making this class's use with those implementations
     * easier.
     *
     * @return {@code true} if the system's stored credential hash is Hex encoded, {@code false} if it
     *         is Base64 encoded.  Default is {@code true}
     */
    public boolean isStoredCredentialsHexEncoded() {
        return storedCredentialsHexEncoded;
    }

    /**
     * Sets the indicator if this system's stored credential hash is Hex encoded or not.
     * <p/>
     * A value of {@code true} will cause this class to decode the system credential from Hex, a
     * value of {@code false} will cause this class to decode the system credential from Base64.
     * <p/>
     * Unless overridden via this method, the default value is {@code true} for convenience - all of Shiro's
     * {@link Hash Hash#toString()} implementations return Hex encoded values by default, making this class's use with
     * those implementations easier.
     *
     * @param storedCredentialsHexEncoded the indicator if this system's stored credential hash is Hex
     *                                    encoded or not ('not' automatically implying it is Base64 encoded).
     */
    public void setStoredCredentialsHexEncoded(boolean storedCredentialsHexEncoded) {
        this.storedCredentialsHexEncoded = storedCredentialsHexEncoded;
    }

    /**
     * Returns {@code true} if a submitted {@code AuthenticationToken}'s credentials should be salted when hashing,
     * {@code false} if it should not be salted.
     * <p/>
     * If enabled, the salt used will be obtained via the {@link #getSalt(AuthenticationToken) getSalt} method.
     * <p/>
     * The default value is {@code false}.
     *
     * @return {@code true} if a submitted {@code AuthenticationToken}'s credentials should be salted when hashing,
     *         {@code false} if it should not be salted.
     */
    public boolean isHashSalted() {
        return hashSalted;
    }

    /**
     * Sets whether or not to salt a submitted {@code AuthenticationToken}'s credentials when hashing.
     * <p/>
     * If enabled, the salt used will be obtained via the {@link #getSalt(org.apache.shiro.authc.AuthenticationToken) getSalt} method.
     * </p>
     * The default value is {@code false}.
     *
     * @param hashSalted whether or not to salt a submitted {@code AuthenticationToken}'s credentials when hashing.
     */
    public void setHashSalted(boolean hashSalted) {
        this.hashSalted = hashSalted;
    }

    /**
     * Returns the number of times a submitted {@code AuthenticationToken}'s credentials will be hashed before
     * comparing to the credentials stored in the system.
     * <p/>
     * Unless overridden, the default value is {@code 1}, meaning a normal hash execution will occur.
     *
     * @return the number of times a submitted {@code AuthenticationToken}'s credentials will be hashed before
     *         comparing to the credentials stored in the system.
     */
    public int getHashIterations() {
        return hashIterations;
    }

    /**
     * Sets the number of times a submitted {@code AuthenticationToken}'s credentials will be hashed before comparing
     * to the credentials stored in the system.
     * <p/>
     * Unless overridden, the default value is {@code 1}, meaning a normal single hash execution will occur.
     * <p/>
     * If this argument is less than 1 (i.e. 0 or negative), the default value of 1 is applied.  There must always be
     * at least 1 hash iteration (otherwise there would be no hash).
     *
     * @param hashIterations the number of times to hash a submitted {@code AuthenticationToken}'s credentials.
     */
    public void setHashIterations(int hashIterations) {
        if (hashIterations < 1) {
            this.hashIterations = 1;
        } else {
            this.hashIterations = hashIterations;
        }
    }

    /**
     * Returns a salt value used to hash the token's credentials.
     * <p/>
     * This default implementation merely returns {@code token.getPrincipal()}, effectively using the user's
     * identity (username, user id, etc) as the salt, a most common technique.  If you wish to provide the
     * authentication token's salt another way, you may override this method.
     *
     * @param token the AuthenticationToken submitted during the authentication attempt.
     * @return a salt value to use to hash the authentication token's credentials.
     */
    protected Object getSalt(AuthenticationToken token) {
        return token.getPrincipal();
    }

    /**
     * As this is a HashedCredentialMatcher, this method overrides the parent method by returning a hashed value
     * of the submitted token's credentials.
     * <p/>
     * Based on this class's configuration, the return value may be salted and/or
     * hashed multiple times (see the class-level JavaDoc for more information on salting and
     * multiple hash iterations).
     *
     * @param token the authentication token submitted during the authentication attempt.
     * @return the hashed value of the authentication token's credentials.
     */
    protected Object getCredentials(AuthenticationToken token) {
        Object credentials = token.getCredentials();
        Object salt = isHashSalted() ? getSalt(token) : null;
        return hashProvidedCredentials(credentials, salt, getHashIterations());
    }

    /**
     * Returns a {@link Hash Hash} instance representing the already-hashed AuthenticationInfo credentials stored in the system.
     * <p/>
     * This method reconstructs a {@link Hash Hash} instance based on a {@code info.getCredentials} call,
     * but it does <em>not</em> hash that value - it is expected that method call will return an already-hashed value.
     * <p/>
     * This implementation's reconstruction effort functions as follows:
     * <ol>
     * <li>Convert {@code account.getCredentials()} to a byte array via the {@link #toBytes toBytes} method.
     * <li>If {@code account.getCredentials()} was originally a String or char[] before {@code toBytes} was
     * called, check for encoding:
     * <li>If {@link #storedCredentialsHexEncoded storedCredentialsHexEncoded}, Hex decode that byte array, otherwise
     * Base64 decode the byte array</li>
     * <li>Set the byte[] array directly on the {@code Hash} implementation and return it.</li>
     * </ol>
     *
     * @param info the AuthenticationInfo from which to retrieve the credentials which assumed to be in already-hashed form.
     * @return a {@link Hash Hash} instance representing the given AuthenticationInfo's stored credentials.
     */
    protected Object getCredentials(AuthenticationInfo info) {
        Object credentials = info.getCredentials();

        byte[] storedBytes = toBytes(credentials);

        if (credentials instanceof String || credentials instanceof char[]) {
            //account.credentials were a char[] or String, so
            //we need to do text decoding first:
            if (isStoredCredentialsHexEncoded()) {
                storedBytes = Hex.decode(storedBytes);
            } else {
                storedBytes = Base64.decode(storedBytes);
            }
        }
        AbstractHash hash = newHashInstance();
        hash.setBytes(storedBytes);
        return hash;
    }

    /**
     * Hashes the provided credentials a total of {@code hashIterations} times, using the given salt.  The hash
     * implementation/algorithm used is left to subclasses.
     *
     * @param credentials    the submitted authentication token's credentials to hash
     * @param salt           the value to salt the hash, or {@code null} if a salt will not be used.
     * @param hashIterations the number of times to hash the credentials.  At least one hash will always occur though,
     *                       even if this argument is 0 or negative.
     * @return the hashed value of the provided credentials, according to the specified salt and hash iterations.
     */
    protected abstract Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations);

    /**
     * Returns a new, <em>uninitialized</em> instance, without its byte array set.  Used as a utility method in the
     * {@link SimpleCredentialsMatcher#getCredentials(org.apache.shiro.authc.AuthenticationInfo) getCredentials(AuthenticationInfo)} implementation.
     *
     * @return a new, <em>uninitialized</em> instance, without its byte array set.
     */
    protected abstract AbstractHash newHashInstance();

}
