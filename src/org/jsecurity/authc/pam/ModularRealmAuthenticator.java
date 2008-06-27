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
package org.jsecurity.authc.pam;

import org.jsecurity.authc.*;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A <tt>ModularRealmAuthenticator</tt> delgates account lookups to a pluggable (modular) collection of
 * {@link Realm}s.  This enables PAM (Pluggable Authentication Module) behavior in JSecurity.
 * In addition to authorization duties, a JSecurity Realm can also be thought of a PAM 'module'.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>Realm</tt>s as you see fit.  Common realms are those based on accessing
 * LDAP, relational databases, file systems, etc.
 *
 * <p>If only one realm is configured (this is often the case for most applications), authentication success is naturally
 * only dependent upon invoking this one Realm's
 * {@link Realm#getAccount(org.jsecurity.authc.AuthenticationToken) getAccount} method.
 *
 * <p>But if two or more realms are configured, PAM behavior is implemented by iterating over the collection of realms
 * and interacting with each over the course of the authentication attempt.  As this is more complicated, this
 * authenticator allows customized behavior for interpreting what happens when interacting with multiple realms - for
 * example, you might require all realms to be successful during the attempt, or perhaps only at least one must be
 * successful, or some other interpretation.  This customized behavior can be performed via the use of a
 * {@link #setModularAuthenticationStrategy(ModularAuthenticationStrategy) ModularAuthenticationStrategy}, which
 * you can inject as a property of this class.
 *
 * <p>The strategy object provides callback methods that allow you to
 * determine what constitutes a success or failure in a multi-realm (PAM) scenario.  And because this only makes sense
 * in a mult-realm scenario, the strategy object is only utilized when more than one Realm is configured.
 *
 * <p>For greater security in a multi-realm configuration, unless overridden, the default implementation is the
 * {@link AllSuccessfulModularAuthenticationStrategy AllSuccessfulModularAuthenticationStrategy}
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @see #setRealms
 * @see AllSuccessfulModularAuthenticationStrategy
 * @see AtLeastOneSuccessfulModularAuthenticationStrategy
 * @since 0.1
 */
public class ModularRealmAuthenticator extends AbstractAuthenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * List of realms that will be iterated through when a user authenticates.
     */
    private Collection<? extends Realm> realms;

    private ModularAuthenticationStrategy modularAuthenticationStrategy =
            new AllSuccessfulModularAuthenticationStrategy();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public ModularRealmAuthenticator() {
        super();
    }

    public ModularRealmAuthenticator(Realm realm) {
        setRealm(realm);
    }

    public ModularRealmAuthenticator(List<Realm> realms) {
        setRealms(realms);
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Convenience setter for single-realm environments (fairly common).  This method just wraps the realm in a
     * collection and then calls {@link #setRealms}.
     *
     * @param realm the realm to consult during authentication attempts.
     */
    public void setRealm(Realm realm) {
        List<Realm> realms = new ArrayList<Realm>(1);
        realms.add(realm);
        setRealms(realms);
    }

    /**
     * Sets all realms used by this Authenticator, providing PAM (Pluggable Authentication Module) configuration.
     *
     * @param realms the realms to consult during authentication attempts.
     */
    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    /**
     * Returns the <tt>ModularAuthenticationStrategy</tt> utilized by this modular authenticator during a multi-realm
     * log-in attempt.  This object is only used when two or more Realms are configured.
     *
     * <p>Unless overridden by
     * the {@link #setModularAuthenticationStrategy(ModularAuthenticationStrategy)} method, the default implementation
     * is the {@link AllSuccessfulModularAuthenticationStrategy}.
     *
     * @return the <tt>ModularAuthenticationStrategy</tt> utilized by this modular authenticator during a log-in attempt.
     * @since 0.2
     */
    public ModularAuthenticationStrategy getModularAuthenticationStrategy() {
        return modularAuthenticationStrategy;
    }

    /**
     * Allows overriding the default <tt>ModularAuthenticationStrategy</tt> utilized during multi-realm log-in attempts.
     * This object is only used when two or more Realms are configured.
     *
     * @param modularAuthenticationStrategy the strategy implementation to use during log-in attempts.
     * @since 0.2
     */
    public void setModularAuthenticationStrategy(ModularAuthenticationStrategy modularAuthenticationStrategy) {
        this.modularAuthenticationStrategy = modularAuthenticationStrategy;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Used by the internal {@link #doAuthenticate} implementation to ensure that the <tt>realms</tt> property
     * has been set.  The default implementation ensures the property is not null and not empty.
     *
     * @throws IllegalStateException if the <tt>realms</tt> property is configured incorrectly.
     */
    protected void assertRealmsConfigured() throws IllegalStateException {
        if (realms == null || realms.isEmpty()) {
            String msg = "No realms configured for this ModularRealmAuthenticator.  Configuration error.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Performs the authentication attempt by interacting with the single configured realm, which is significantly
     * simpler than performing multi-realm logic.
     *
     * @param realm the realm to consult for Account.
     * @param token the submitted AuthenticationToken representing the subject's (user's) log-in principals and credentials.
     * @return the Account associated with the user account corresponding to the specified <tt>token</tt>
     */
    protected Account doSingleRealmAuthentication(Realm realm, AuthenticationToken token) {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] does not support authentication token [" +
                    token + "].  Please ensure that the appropriate Realm implementation is " +
                    "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
        }
        Account account = realm.getAccount(token);
        if (account == null) {
            String msg = "Realm [" + realm + "] was unable to find account data for the " +
                    "submitted AuthenticationToken [" + token + "].";
            throw new UnknownAccountException(msg);
        }
        return account;
    }

    /**
     * Performs the multi-realm authentication attempt by calling back to a {@link ModularAuthenticationStrategy} object
     * as each realm is consulted for <tt>Account</tt> for the specified <tt>token</tt>.
     *
     * @param realms the multiple realms configured on this Authenticator instance.
     * @param token  the submitted AuthenticationToken representing the subject's (user's) log-in principals and credentials.
     * @return an aggregated Account instance representing account data across all the successfully
     *         consulted realms.
     */
    protected Account doMultiRealmAuthentication(Collection<? extends Realm> realms, AuthenticationToken token) {

        ModularAuthenticationStrategy strategy = getModularAuthenticationStrategy();

        Account aggregate = strategy.beforeAllAttempts(realms, token);

        if (log.isDebugEnabled()) {
            log.debug("Iterating through [" + realms.size() + "] realms for PAM authentication");
        }

        for (Realm realm : realms) {

            aggregate = strategy.beforeAttempt(realm, token, aggregate);

            if (realm.supports(token)) {

                if (log.isDebugEnabled()) {
                    log.debug("Attempting to authenticate token [" + token + "] " +
                            "using realm of type [" + realm + "]");
                }

                Account account = null;
                Throwable t = null;
                try {
                    account = realm.getAccount(token);
                } catch (Throwable throwable) {
                    t = throwable;
                    if (log.isTraceEnabled()) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.trace(msg, t);
                    }
                }

                aggregate = strategy.afterAttempt(realm, token, account, aggregate, t);

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Realm of type [" + realm + "] does not support token " +
                            "[" + token + "].  Skipping realm.");
                }
            }
        }

        aggregate = strategy.afterAllAttempts(token, aggregate);

        return aggregate;
    }


    /**
     * <p>Attempts to authenticate the given token by iterating over the internal collection of
     * {@link Realm}s.  For each realm, first the {@link Realm#supports(org.jsecurity.authc.AuthenticationToken)}
     * method will be called to determine if the realm supports the <tt>authenticationToken</tt> method argument.
     *
     * If a realm does support
     * the token, its {@link Realm#getAccount(org.jsecurity.authc.AuthenticationToken)}
     * method will be called.  If the realm returns a non-null account, the token will be
     * considered authenticated for that realm and the account data recorded.  If the realm returns <tt>null</tt>,
     * the next realm will be consulted.  If no realms support the token or all supporting realms return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     *
     * <p>After all realms have been consulted, the information from each realm is aggregated into a single
     * {@link org.jsecurity.authc.Account} object and returned.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     *                            user being authenticated.
     * @return account information attributed to the authenticated user.
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     *                                 for the given principal and credentials.
     */
    protected Account doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        assertRealmsConfigured();

        if (realms.size() == 1) {
            return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
        } else {
            return doMultiRealmAuthentication(realms, authenticationToken);
        }
    }

    /**
     * First calls <code>super.onLogout(principals)</code> to ensure a logout event is sent, and for each
     * wrapped <tt>Realm</tt> that implements the {@link LogoutAware LogoutAware} interface, calls
     * <code>((LogoutAware)realm).onLogout(principals)</code> to allow each realm the opportunity to perform
     * logout/cleanup operations during an user-logout.
     *
     * <p>JSecurity's Realm implementations all implement the <tt>LogoutAware</tt> interface by default and can be
     * overridden for realm-specific logout logic.
     *
     * @param principals the application-specific Subject/user identifier.
     */
    public void onLogout(PrincipalCollection principals) {
        super.onLogout(principals);
        if (realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof LogoutAware) {
                    ((LogoutAware) realm).onLogout(principals);
                }
            }
        }
    }
}