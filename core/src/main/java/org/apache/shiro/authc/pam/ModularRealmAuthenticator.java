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
package org.apache.shiro.authc.pam;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * A {@code ModularRealmAuthenticator} delgates account lookups to a pluggable (modular) collection of
 * {@link Realm}s.  This enables PAM (Pluggable Authentication Module) behavior in Shiro.
 * In addition to authorization duties, a Shiro Realm can also be thought of a PAM 'module'.
 * <p/>
 * Using this Authenticator allows you to &quot;plug-in&quot; your own
 * {@code Realm}s as you see fit.  Common realms are those based on accessing
 * LDAP, relational databases, file systems, etc.
 * <p/>
 * If only one realm is configured (this is often the case for most applications), authentication success is naturally
 * only dependent upon invoking this one Realm's
 * {@link Realm#getAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)} method.
 * <p/>
 * But if two or more realms are configured, PAM behavior is implemented by iterating over the collection of realms
 * and interacting with each over the course of the authentication attempt.  As this is more complicated, this
 * authenticator allows customized behavior for interpreting what happens when interacting with multiple realms - for
 * example, you might require all realms to be successful during the attempt, or perhaps only at least one must be
 * successful, or some other interpretation.  This customized behavior can be performed via the use of a
 * {@link #setAuthenticationStrategy(AuthenticationStrategy) AuthenticationStrategy}, which
 * you can inject as a property of this class.
 * <p/>
 * The strategy object provides callback methods that allow you to
 * determine what constitutes a success or failure in a multi-realm (PAM) scenario.  And because this only makes sense
 * in a mult-realm scenario, the strategy object is only utilized when more than one Realm is configured.
 * <p/>
 * As most multi-realm applications require at least one Realm authenticates successfully, the default
 * implementation is the {@link AtLeastOneSuccessfulStrategy}.
 *
 * @see #setRealms
 * @see AtLeastOneSuccessfulStrategy
 * @see AllSuccessfulStrategy
 * @see FirstSuccessfulStrategy
 * @since 0.1
 */
public class ModularRealmAuthenticator extends AbstractAuthenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final Logger log = LoggerFactory.getLogger(ModularRealmAuthenticator.class);

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * List of realms that will be iterated through when a user authenticates.
     */
    private Collection<Realm> realms;

    /**
     * The authentication strategy to use during authentication attempts, defaults to a
     * {@link org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy} instance.
     */
    private AuthenticationStrategy authenticationStrategy;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * Default no-argument constructor which
     * {@link #setAuthenticationStrategy(AuthenticationStrategy) enables}  an
     * {@link org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy} by default.
     */
    public ModularRealmAuthenticator() {
        this.authenticationStrategy = new AtLeastOneSuccessfulStrategy();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets all realms used by this Authenticator, providing PAM (Pluggable Authentication Module) configuration.
     *
     * @param realms the realms to consult during authentication attempts.
     */
    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    /**
     * Returns the realm(s) used by this {@code Authenticator} during an authentication attempt.
     *
     * @return the realm(s) used by this {@code Authenticator} during an authentication attempt.
     */
    protected Collection<Realm> getRealms() {
        return this.realms;
    }

    /**
     * Returns the {@code AuthenticationStrategy} utilized by this modular authenticator during a multi-realm
     * log-in attempt.  This object is only used when two or more Realms are configured.
     * <p/>
     * Unless overridden by
     * the {@link #setAuthenticationStrategy(AuthenticationStrategy)} method, the default implementation
     * is the {@link org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy}.
     *
     * @return the {@code AuthenticationStrategy} utilized by this modular authenticator during a log-in attempt.
     * @since 0.2
     */
    public AuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    /**
     * Allows overriding the default {@code AuthenticationStrategy} utilized during multi-realm log-in attempts.
     * This object is only used when two or more Realms are configured.
     *
     * @param authenticationStrategy the strategy implementation to use during log-in attempts.
     * @since 0.2
     */
    public void setAuthenticationStrategy(AuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    /*--------------------------------------------
    |               M E T H O D S               |

    /**
     * Used by the internal {@link #doAuthenticate} implementation to ensure that the {@code realms} property
     * has been set.  The default implementation ensures the property is not null and not empty.
     *
     * @throws IllegalStateException if the {@code realms} property is configured incorrectly.
     */

    protected void assertRealmsConfigured() throws IllegalStateException {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be " +
                    "present to execute an authentication attempt.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Performs the authentication attempt by interacting with the single configured realm, which is significantly
     * simpler than performing multi-realm logic.
     *
     * @param realm the realm to consult for AuthenticationInfo.
     * @param token the submitted AuthenticationToken representing the subject's (user's) log-in principals and credentials.
     * @return the AuthenticationInfo associated with the user account corresponding to the specified {@code token}
     */
    protected AuthenticationInfo doSingleRealmAuthentication(Realm realm, AuthenticationToken token) {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] does not support authentication token [" +
                    token + "].  Please ensure that the appropriate Realm implementation is " +
                    "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
        }
        AuthenticationInfo info = realm.getAuthenticationInfo(token);
        if (info == null) {
            String msg = "Realm [" + realm + "] was unable to find account data for the " +
                    "submitted AuthenticationToken [" + token + "].";
            throw new UnknownAccountException(msg);
        }
        return info;
    }

    /**
     * Performs the multi-realm authentication attempt by calling back to a {@link AuthenticationStrategy} object
     * as each realm is consulted for {@code AuthenticationInfo} for the specified {@code token}.
     *
     * @param realms the multiple realms configured on this Authenticator instance.
     * @param token  the submitted AuthenticationToken representing the subject's (user's) log-in principals and credentials.
     * @return an aggregated AuthenticationInfo instance representing account data across all the successfully
     *         consulted realms.
     */
    protected AuthenticationInfo doMultiRealmAuthentication(Collection<Realm> realms, AuthenticationToken token) {

        AuthenticationStrategy strategy = getAuthenticationStrategy();

        AuthenticationInfo aggregate = strategy.beforeAllAttempts(realms, token);

        if (log.isTraceEnabled()) {
            log.trace("Iterating through {} realms for PAM authentication", realms.size());
        }

        for (Realm realm : realms) {

            if (realm.supports(token)) {

                log.trace("Attempting to authenticate token [{}] using realm [{}]", token, realm);

                AuthenticationInfo info = null;
                Throwable t = null;
                try {
                    info = realm.getAuthenticationInfo(token);
                } catch (Throwable throwable) {
                    t = throwable;
                    if (log.isDebugEnabled()) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.debug(msg, t);
                    }
                }

                aggregate = strategy.afterAttempt(realm, token, info, aggregate, t);

            } else {
                log.debug("Realm [{}] does not support token {}.  Skipping realm.", realm, token);
            }
        }

        aggregate = strategy.afterAllAttempts(token, aggregate);

        return aggregate;
    }


    /**
     * Attempts to authenticate the given token by iterating over the internal collection of
     * {@link Realm}s.  For each realm, first the {@link Realm#supports(org.apache.shiro.authc.AuthenticationToken)}
     * method will be called to determine if the realm supports the {@code authenticationToken} method argument.
     * <p/>
     * If a realm does support
     * the token, its {@link Realm#getAuthenticationInfo(org.apache.shiro.authc.AuthenticationToken)}
     * method will be called.  If the realm returns a non-null account, the token will be
     * considered authenticated for that realm and the account data recorded.  If the realm returns {@code null},
     * the next realm will be consulted.  If no realms support the token or all supporting realms return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     * <p/>
     * After all realms have been consulted, the information from each realm is aggregated into a single
     * {@link AuthenticationInfo} object and returned.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     *                            user being authenticated.
     * @return account information attributed to the authenticated user.
     * @throws IllegalStateException   if no realms have been configured at the time this method is invoked
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     *                                 for the given principal and credentials.
     */
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        assertRealmsConfigured();
        Collection<Realm> realms = getRealms();
        if (realms.size() == 1) {
            return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
        } else {
            return doMultiRealmAuthentication(realms, authenticationToken);
        }
    }

    /**
     * First calls <code>super.onLogout(principals)</code> to ensure a logout notification is issued, and for each
     * wrapped {@code Realm} that implements the {@link LogoutAware LogoutAware} interface, calls
     * <code>((LogoutAware)realm).onLogout(principals)</code> to allow each realm the opportunity to perform
     * logout/cleanup operations during an user-logout.
     * <p/>
     * Shiro's Realm implementations all implement the {@code LogoutAware} interface by default and can be
     * overridden for realm-specific logout logic.
     *
     * @param principals the application-specific Subject/user identifier.
     */
    public void onLogout(PrincipalCollection principals) {
        super.onLogout(principals);
        Collection<Realm> realms = getRealms();
        if (realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof LogoutAware) {
                    ((LogoutAware) realm).onLogout(principals);
                }
            }
        }
    }
}
