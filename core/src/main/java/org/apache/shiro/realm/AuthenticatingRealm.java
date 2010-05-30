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
package org.apache.shiro.realm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LogoutAware;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.PrincipalCollection;


/**
 * A top-level abstract implementation of the <tt>Realm</tt> interface that only implements authentication support
 * (log-in) operations and leaves authorization (access control) behavior to subclasses.
 *
 * <p>Since a Realm provides both authentication <em>and</em> authorization operations, the implementation approach for
 * this class could have been reversed.  That is, authorization support could have been implemented here and
 * authentication support left to subclasses.
 *
 * <p>The reason the existing implementation is in place though
 * (authentication support) is that most authentication operations are fairly common across the large majority of
 * applications, whereas authorization operations are more so heavily dependent upon the application's data model, which
 * can vary widely.
 *
 * <p>By providing the most common authentication operations here and leaving data-model specific authorization checks
 * to subclasses, a top-level abstract class for most common authentication behavior is more useful as an extension
 * point for most applications.
 *
 * @since 0.2
 */
public abstract class AuthenticatingRealm extends CachingRealm implements LogoutAware {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(AuthenticatingRealm.class);

    /**
     * Password matcher used to determine if the provided password matches
     * the password stored in the data store.
     */
    private CredentialsMatcher credentialsMatcher = new SimpleCredentialsMatcher();

    /**
     * The class that this realm supports for authentication tokens.  This is used by the
     * default implementation of the {@link Realm#supports(org.apache.shiro.authc.AuthenticationToken)} method to
     * determine whether or not the given authentication token is supported by this realm.
     */
    private Class<? extends AuthenticationToken> authenticationTokenClass = UsernamePasswordToken.class;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthenticatingRealm() {
    }

    public AuthenticatingRealm(CacheManager cacheManager) {
        setCacheManager(cacheManager);
    }

    public AuthenticatingRealm(CredentialsMatcher matcher) {
        setCredentialsMatcher(matcher);
    }

    public AuthenticatingRealm(CacheManager cacheManager, CredentialsMatcher matcher) {
        setCacheManager(cacheManager);
        setCredentialsMatcher(matcher);
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Returns the <code>CredentialsMatcher</code> used during an authentication attempt to verify submitted
     * credentials with those stored in the system.
     *
     * <p>Unless overridden by the {@link #setCredentialsMatcher setCredentialsMatcher} method, the default
     * value is a {@link org.apache.shiro.authc.credential.SimpleCredentialsMatcher SimpleCredentialsMatcher} instance.
     *
     * @return the <code>CredentialsMatcher</code> used during an authentication attempt to verify submitted
     *         credentials with those stored in the system.
     */
    public CredentialsMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    /**
     * Sets the CrendialsMatcher used during an authentication attempt to verify submitted credentials with those
     * stored in the system.  The implementation of this matcher can be switched via configuration to
     * support any number of schemes, including plain text comparisons, hashing comparisons, and others.
     *
     * <p>Unless overridden by this method, the default value is a
     * {@link org.apache.shiro.authc.credential.SimpleCredentialsMatcher} instance.
     *
     * @param credentialsMatcher the matcher to use.
     */
    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        this.credentialsMatcher = credentialsMatcher;
    }

    /**
     * Returns the authenticationToken class supported by this realm.
     *
     * <p>The default value is <tt>{@link org.apache.shiro.authc.UsernamePasswordToken UsernamePasswordToken.class}</tt>, since
     * about 90% of realms use username/password authentication, regardless of their protocol (e.g. over jdbc, ldap,
     * kerberos, http, etc).
     *
     * <p>If subclasses haven't already overridden the {@link Realm#supports Realm.supports(AuthenticationToken)} method,
     * they must {@link #setAuthenticationTokenClass(Class) set a new class} if they won't support
     * <tt>UsernamePasswordToken</tt> authentication token submissions.
     *
     * @return the authenticationToken class supported by this realm.
     * @see #setAuthenticationTokenClass
     */
    public Class getAuthenticationTokenClass() {
        return authenticationTokenClass;
    }

    /**
     * Sets the authenticationToken class supported by this realm.
     *
     * <p>Unless overridden by this method, the default value is
     * {@link org.apache.shiro.authc.UsernamePasswordToken UsernamePasswordToken.class} to support the majority of applications.
     *
     * @param authenticationTokenClass the class of authentication token instances supported by this realm.
     * @see #getAuthenticationTokenClass getAuthenticationTokenClass() for more explanation.
     */
    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        this.authenticationTokenClass = authenticationTokenClass;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Convenience implementation that returns
     * <tt>getAuthenticationTokenClass().isAssignableFrom( token.getClass() );</tt>.  Can be overridden
     * by subclasses for more complex token checking.
     * <p>Most configurations will only need to set a different class via
     * {@link #setAuthenticationTokenClass}, as opposed to overriding this method.
     *
     * @param token the token being submitted for authentication.
     * @return true if this authentication realm can process the submitted token instance of the class, false otherwise.
     */
    public boolean supports(AuthenticationToken token) {
        return token != null && getAuthenticationTokenClass().isAssignableFrom(token.getClass());
    }

    public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        AuthenticationInfo info = doGetAuthenticationInfo(token);

        if (info == null) {
            if (log.isDebugEnabled()) {
                String msg = "No authentication information found for submitted authentication token [" + token + "].  " +
                        "Returning null.";
                log.debug(msg);
            }
            return null;
        }

        CredentialsMatcher cm = getCredentialsMatcher();
        if (cm != null) {
            if (!cm.doCredentialsMatch(token, info)) {
                String msg = "The credentials provided for account [" + token +
                        "] did not match the expected credentials.";
                throw new IncorrectCredentialsException(msg);
            }
        } else {
            throw new AuthenticationException("A CredentialsMatcher must be configured in order to verify " +
                    "credentials during authentication.  If you do not wish for credentials to be examined, you " +
                    "can configure an " + AllowAllCredentialsMatcher.class.getName() + " instance.");
        }

        return info;
    }

    /**
     * Retrieves authentication data from an implementation-specific datasource (RDBMS, LDAP, etc) for the given
     * authentication token.
     *
     * <p>For most datasources, this means just 'pulling' authentication data for an associated subject/user and nothing
     * more and letting Shiro do the rest.  But in some systems, this method could actually perform EIS specific
     * log-in logic in addition to just retrieving data - it is up to the Realm implementation.
     *
     * <p>A <tt>null</tt> return value means that no account could be associated with the specified token.
     *
     * @param token the authentication token containing the user's principal and credentials.
     * @return an {@link AuthenticationInfo} object containing account data resulting from the
     *         authentication ONLY if the lookup is successful (i.e. account exists and is valid, etc.)
     * @throws org.apache.shiro.authc.AuthenticationException
     *          if there is an error acquiring data or performing
     *          realm-specific authentication logic for the specified <tt>token</tt>
     */
    protected abstract AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

    /**
     * Default implementation that does nothing (no-op) and exists as a convenience mechanism in case subclasses
     * wish to override it to implement realm-specific logout logic for the given user account logging out.</p>
     * <p/>
     * In a single-realm Shiro configuration (most applications), the <code>principals</code> method
     * argument will be the same as that which is contained in the <code>AuthenticationInfo</code> object returned by the
     * {@link #doGetAuthenticationInfo} method (that is, {@link AuthenticationInfo#getPrincipals info.getPrincipals()}).
     * <p/>
     * In a multi-realm Shiro configuration, the given <code>principals</code> method
     * argument could contain principals returned by many realms.  Therefore the subclass implementation would need
     * to know how to extract the principal(s) relevant to only itself and ignore other realms' principals.  This is
     * usually done by calling {@link org.apache.shiro.subject.PrincipalCollection#fromRealm(String) principals.fromRealm(name)},
     * using the realm's own {@link Realm#getName() name}.
     *
     * @param principals the application-specific Subject/user identifier that is logging out.
     */
    public void onLogout(PrincipalCollection principals) {
        //no-op, here for subclass override if desired.
    }

}
