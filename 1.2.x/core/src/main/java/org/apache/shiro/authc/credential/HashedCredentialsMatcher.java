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
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.hash.AbstractHash;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.StringUtils;

/**
 * A {@code HashedCredentialMatcher} provides support for hashing of supplied {@code AuthenticationToken} credentials
 * before being compared to those in the {@code AuthenticationInfo} from the data store.
 * <p/>
 * Credential hashing is one of the most common security techniques when safeguarding a user's private credentials
 * (passwords, keys, etc).  Most developers never want to store their users' credentials in plain form, viewable by
 * anyone, so they often hash the users' credentials before they are saved in the data store.
 * <p/>
 * This class (and its subclasses) function as follows:
 * <ol>
 * <li>Hash the {@code AuthenticationToken} credentials supplied by the user during their login.</li>
 * <li>Compare this hashed value directly with the {@code AuthenticationInfo} credentials stored in the system
 * (the stored account credentials are expected to already be in hashed form).</li>
 * <li>If these two values are {@link #equals(Object, Object) equal}, the submitted credentials match, otherwise
 * they do not.</li>
 * </ol>
 * <h2>Salting and Multiple Hash Iterations</h2>
 * Because simple hashing is usually not good enough for secure applications, this class also supports 'salting'
 * and multiple hash iterations.  Please read this excellent
 * <a href="http://www.owasp.org/index.php/Hashing_Java" _target="blank">Hashing Java article</a> to learn about
 * salting and multiple iterations and why you might want to use them. (Note of sections 5
 * &quot;Why add salt?&quot; and 6 "Hardening against the attacker's attack").   We should also note here that all of
 * Shiro's Hash implementations (for example, {@link org.apache.shiro.crypto.hash.Md5Hash Md5Hash},
 * {@link org.apache.shiro.crypto.hash.Sha1Hash Sha1Hash}, etc) support salting and multiple hash iterations via
 * overloaded constructors.
 * <h4>Real World Case Study</h4>
 * In April 2010, some public Atlassian Jira and Confluence
 * installations (Apache Software Foundation, Codehaus, etc) were the target of account attacks and user accounts
 * were compromised.  The reason?  Jira and Confluence at the time did not salt user passwords and attackers were
 * able to use dictionary attacks to compromise user accounts (Atlassian has since
 * <a href="http://blogs.atlassian.com/news/2010/04/oh_man_what_a_day_an_update_on_our_security_breach.html">
 * fixed the problem</a> of course).
 * <p/>
 * The lesson?
 * <p/>
 * <b>ALWAYS, ALWAYS, ALWAYS SALT USER PASSWORDS!</b>
 * <p/>
 * <h3>Salting</h3>
 * Prior to Shiro 1.1, salts could be obtained based on the end-user submitted
 * {@link AuthenticationToken AuthenticationToken} via the now-deprecated
 * {@link #getSalt(org.apache.shiro.authc.AuthenticationToken) getSalt(AuthenticationToken)} method.  This however
 * could constitute a security hole since ideally salts should never be obtained based on what a user can submit.
 * User-submitted salt mechanisms are <em>much</em> more susceptible to dictionary attacks and <b>SHOULD NOT</b> be
 * used in secure systems.  Instead salts should ideally be a secure randomly-generated number that is generated when
 * the user account is created.  The secure number should never be disseminated to the user and always kept private
 * by the application.
 * <h4>Shiro 1.1</h4>
 * As of Shiro 1.1, it is expected that any salt used to hash the submitted credentials will be obtained from the
 * stored account information (represented as an {@link AuthenticationInfo AuthenticationInfo} instance).  This is much
 * more secure because the salt value remains private to the application (Shiro will never store this value).
 * <p/>
 * To enable this, {@code Realm}s should return {@link SaltedAuthenticationInfo SaltedAuthenticationInfo} instances
 * during authentication.  {@code HashedCredentialsMatcher} implementations will then use the provided
 * {@link org.apache.shiro.authc.SaltedAuthenticationInfo#getCredentialsSalt credentialsSalt} for hashing.  To avoid
 * security risks,
 * <b>it is highly recommended that any existing {@code Realm} implementations that support hashed credentials are
 * updated to return {@link SaltedAuthenticationInfo SaltedAuthenticationInfo} instances as soon as possible</b>.
 * <h4>Shiro 1.0 Backwards Compatibility</h4>
 * Because of the identified security risk, {@code Realm} implementations that support credentials hashing should
 * be updated to return {@link SaltedAuthenticationInfo SaltedAuthenticationInfo} instances as
 * soon as possible.
 * <p/>
 * If this is not possible for some reason, this class will retain 1.0 backwards-compatible behavior of obtaining
 * the salt via the now-deprecated {@link #getSalt(AuthenticationToken) getSalt(AuthenticationToken)} method.  This
 * method will only be invoked if a {@code Realm} <em>does not</em> return
 * {@link SaltedAuthenticationInfo SaltedAutenticationInfo} instances and {@link #isHashSalted() hashSalted} is
 * {@code true}.
 * But please note that the {@link #isHashSalted() hashSalted} property and the
 * {@link #getSalt(AuthenticationToken) getSalt(AuthenticationToken)} methods will be removed before the Shiro 2.0
 * release.
 * <h3>Multiple Hash Iterations</h3>
 * If you hash your users' credentials multiple times before persisting to the data store, you will also need to
 * set this class's {@link #setHashIterations(int) hashIterations} property.  See the
 * <a href="http://www.owasp.org/index.php/Hashing_Java" _target="blank">Hashing Java article</a>'s
 * <a href="http://www.owasp.org/index.php/Hashing_Java#Hardening_against_the_attacker.27s_attack">
 * &quot;Hardening against the attacker's attack&quot;</a> section to learn more about why you might want to use
 * multiple hash iterations.
 * <h2>MD5 &amp; SHA-1 Notice</h2>
 * <a href="http://en.wikipedia.org/wiki/MD5">MD5</a> and
 * <a href="http://en.wikipedia.org/wiki/SHA_hash_functions">SHA-1</a> algorithms are now known to be vulnerable to
 * compromise and/or collisions (read the linked pages for more).  While most applications are ok with either of these
 * two, if your application mandates high security, use the SHA-256 (or higher) hashing algorithms and their
 * supporting {@code CredentialsMatcher} implementations.
 *
 * @see org.apache.shiro.crypto.hash.Md5Hash
 * @see org.apache.shiro.crypto.hash.Sha1Hash
 * @see org.apache.shiro.crypto.hash.Sha256Hash
 * @since 0.9
 */
public class HashedCredentialsMatcher extends SimpleCredentialsMatcher {

    /**
     * @since 1.1
     */
    private String hashAlgorithm;
    private int hashIterations;
    private boolean hashSalted;
    private boolean storedCredentialsHexEncoded;

    /**
     * JavaBeans-compatibile no-arg constructor intended for use in IoC/Dependency Injection environments.  If you
     * use this constructor, you <em>MUST</em> also additionally set the
     * {@link #setHashAlgorithmName(String) hashAlgorithmName} property.
     */
    public HashedCredentialsMatcher() {
        this.hashAlgorithm = null;
        this.hashSalted = false;
        this.hashIterations = 1;
        this.storedCredentialsHexEncoded = true; //false means Base64-encoded
    }

    /**
     * Creates an instance using the specified {@link #getHashAlgorithmName() hashAlgorithmName} to hash submitted
     * credentials.
     * @param hashAlgorithmName the {@code Hash} {@link org.apache.shiro.crypto.hash.Hash#getAlgorithmName() algorithmName}
     *                          to use when performing hashes for credentials matching.
     * @since 1.1
     */
    public HashedCredentialsMatcher(String hashAlgorithmName) {
        this();
        if (!StringUtils.hasText(hashAlgorithmName) ) {
            throw new IllegalArgumentException("hashAlgorithmName cannot be null or empty.");
        }
        this.hashAlgorithm = hashAlgorithmName;
    }

    /**
     * Returns the {@code Hash} {@link org.apache.shiro.crypto.hash.Hash#getAlgorithmName() algorithmName} to use
     * when performing hashes for credentials matching.
     *
     * @return the {@code Hash} {@link org.apache.shiro.crypto.hash.Hash#getAlgorithmName() algorithmName} to use
     *         when performing hashes for credentials matching.
     * @since 1.1
     */
    public String getHashAlgorithmName() {
        return hashAlgorithm;
    }

    /**
     * Sets the {@code Hash} {@link org.apache.shiro.crypto.hash.Hash#getAlgorithmName() algorithmName} to use
     * when performing hashes for credentials matching.
     *
     * @param hashAlgorithmName the {@code Hash} {@link org.apache.shiro.crypto.hash.Hash#getAlgorithmName() algorithmName}
     *                          to use when performing hashes for credentials matching.
     * @since 1.1
     */
    public void setHashAlgorithmName(String hashAlgorithmName) {
        this.hashAlgorithm = hashAlgorithmName;
    }

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
     * @deprecated since Shiro 1.1.  Hash salting is now expected to be based on if the {@link AuthenticationInfo}
     *             returned from the {@code Realm} is a {@link SaltedAuthenticationInfo} instance and its
     *             {@link org.apache.shiro.authc.SaltedAuthenticationInfo#getCredentialsSalt() getCredentialsSalt()} method returns a non-null value.
     *             This method and the 1.0 behavior still exists for backwards compatibility if the {@code Realm} does not return
     *             {@code SaltedAuthenticationInfo} instances, but <b>it is highly recommended that {@code Realm} implementations
     *             that support hashed credentials start returning {@link SaltedAuthenticationInfo SaltedAuthenticationInfo}
     *             instances as soon as possible</b>.
     *             <p/>
     *             This is because salts should always be obtained from the stored account information and
     *             never be interpreted based on user/Subject-entered data.  User-entered data is easier to compromise for
     *             attackers, whereas account-unique (and secure randomly-generated) salts never disseminated to the end-user
     *             are almost impossible to break.  This method will be removed in Shiro 2.0.
     */
    @Deprecated
    public boolean isHashSalted() {
        return hashSalted;
    }

    /**
     * Sets whether or not to salt a submitted {@code AuthenticationToken}'s credentials when hashing.
     * <p/>
     * If enabled, the salt used will be obtained via the {@link #getSalt(org.apache.shiro.authc.AuthenticationToken) getCredentialsSalt} method.
     * </p>
     * The default value is {@code false}.
     *
     * @param hashSalted whether or not to salt a submitted {@code AuthenticationToken}'s credentials when hashing.
     * @deprecated since Shiro 1.1.  Hash salting is now expected to be based on if the {@link AuthenticationInfo}
     *             returned from the {@code Realm} is a {@link SaltedAuthenticationInfo} instance and its
     *             {@link org.apache.shiro.authc.SaltedAuthenticationInfo#getCredentialsSalt() getCredentialsSalt()} method returns a non-null value.
     *             This method and the 1.0 behavior still exists for backwards compatibility if the {@code Realm} does not return
     *             {@code SaltedAuthenticationInfo} instances, but <b>it is highly recommended that {@code Realm} implementations
     *             that support hashed credentials start returning {@link SaltedAuthenticationInfo SaltedAuthenticationInfo}
     *             instances as soon as possible</b>.
     *             <p/>
     *             This is because salts should always be obtained from the stored account information and
     *             never be interpreted based on user/Subject-entered data.  User-entered data is easier to compromise for
     *             attackers, whereas account-unique (and secure randomly-generated) salts never disseminated to the end-user
     *             are almost impossible to break.  This method will be removed in Shiro 2.0.
     */
    @Deprecated
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
     * @deprecated since Shiro 1.1.  Hash salting is now expected to be based on if the {@link AuthenticationInfo}
     *             returned from the {@code Realm} is a {@link SaltedAuthenticationInfo} instance and its
     *             {@link org.apache.shiro.authc.SaltedAuthenticationInfo#getCredentialsSalt() getCredentialsSalt()} method returns a non-null value.
     *             This method and the 1.0 behavior still exists for backwards compatibility if the {@code Realm} does not return
     *             {@code SaltedAuthenticationInfo} instances, but <b>it is highly recommended that {@code Realm} implementations
     *             that support hashed credentials start returning {@link SaltedAuthenticationInfo SaltedAuthenticationInfo}
     *             instances as soon as possible</b>.<p/>
     *             This is because salts should always be obtained from the stored account information and
     *             never be interpreted based on user/Subject-entered data.  User-entered data is easier to compromise for
     *             attackers, whereas account-unique (and secure randomly-generated) salts never disseminated to the end-user
     *             are almost impossible to break.  This method will be removed in Shiro 2.0.
     */
    @Deprecated
    protected Object getSalt(AuthenticationToken token) {
        return token.getPrincipal();
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
     * This implementation first hashes the {@code token}'s credentials, potentially using a
     * {@code salt} if the {@code info} argument is a
     * {@link org.apache.shiro.authc.SaltedAuthenticationInfo SaltedAuthenticationInfo}.  It then compares the hash
     * against the {@code AuthenticationInfo}'s
     * {@link #getCredentials(org.apache.shiro.authc.AuthenticationInfo) already-hashed credentials}.  This method
     * returns {@code true} if those two values are {@link #equals(Object, Object) equal}, {@code false} otherwise.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt.
     * @param info  the {@code AuthenticationInfo} stored in the system matching the token principal
     * @return {@code true} if the provided token credentials hash match to the stored account credentials hash,
     *         {@code false} otherwise
     * @since 1.1
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Object tokenHashedCredentials = hashProvidedCredentials(token, info);
        Object accountCredentials = getCredentials(info);
        return equals(tokenHashedCredentials, accountCredentials);
    }

    /**
     * Hash the provided {@code token}'s credentials using the salt stored with the account if the
     * {@code info} instance is an {@code instanceof} {@link SaltedAuthenticationInfo SaltedAuthenticationInfo} (see
     * the class-level JavaDoc for why this is the preferred approach).
     * <p/>
     * If the {@code info} instance is <em>not</em>
     * an {@code instanceof} {@code SaltedAuthenticationInfo}, the logic will fall back to Shiro 1.0
     * backwards-compatible logic:  it will first check to see {@link #isHashSalted() isHashSalted} and if so, will try
     * to acquire the salt from {@link #getSalt(AuthenticationToken) getSalt(AuthenticationToken)}.  See the class-level
     * JavaDoc for why this is not recommended.  This 'fallback' logic exists only for backwards-compatibility.
     * {@code Realm}s should be updated as soon as possible to return {@code SaltedAuthenticationInfo} instances
     * if account credentials salting is enabled (highly recommended for password-based systems).
     *
     * @param token the submitted authentication token from which its credentials will be hashed
     * @param info  the stored account data, potentially used to acquire a salt
     * @return the token credentials hash
     * @since 1.1
     */
    protected Object hashProvidedCredentials(AuthenticationToken token, AuthenticationInfo info) {
        Object salt = null;
        if (info instanceof SaltedAuthenticationInfo) {
            salt = ((SaltedAuthenticationInfo) info).getCredentialsSalt();
        } else {
            //retain 1.0 backwards compatibility:
            if (isHashSalted()) {
                salt = getSalt(token);
            }
        }
        return hashProvidedCredentials(token.getCredentials(), salt, getHashIterations());
    }

    /**
     * Returns the {@link #getHashAlgorithmName() hashAlgorithmName} property, but will throw an
     * {@link IllegalStateException} if it has not been set.
     *
     * @return the required {@link #getHashAlgorithmName() hashAlgorithmName} property
     * @throws IllegalStateException if the property has not been set prior to calling this method.
     * @since 1.1
     */
    private String assertHashAlgorithmName() throws IllegalStateException {
        String hashAlgorithmName = getHashAlgorithmName();
        if (hashAlgorithmName == null) {
            String msg = "Required 'hashAlgorithmName' property has not been set.  This is required to execute " +
                    "the hashing algorithm.";
            throw new IllegalStateException(msg);
        }
        return hashAlgorithmName;
    }

    /**
     * Hashes the provided credentials a total of {@code hashIterations} times, using the given salt.  The hash
     * implementation/algorithm used is based on the {@link #getHashAlgorithmName() hashAlgorithmName} property.
     *
     * @param credentials    the submitted authentication token's credentials to hash
     * @param salt           the value to salt the hash, or {@code null} if a salt will not be used.
     * @param hashIterations the number of times to hash the credentials.  At least one hash will always occur though,
     *                       even if this argument is 0 or negative.
     * @return the hashed value of the provided credentials, according to the specified salt and hash iterations.
     */
    protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
        String hashAlgorithmName = assertHashAlgorithmName();
        return new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
    }

    /**
     * Returns a new, <em>uninitialized</em> instance, without its byte array set.  Used as a utility method in the
     * {@link SimpleCredentialsMatcher#getCredentials(org.apache.shiro.authc.AuthenticationInfo) getCredentials(AuthenticationInfo)} implementation.
     *
     * @return a new, <em>uninitialized</em> instance, without its byte array set.
     */
    protected AbstractHash newHashInstance() {
        String hashAlgorithmName = assertHashAlgorithmName();
        return new SimpleHash(hashAlgorithmName);
    }

}
