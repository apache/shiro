/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
package org.jsecurity.authc.support;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UnknownAccountException;
import org.jsecurity.realm.Realm;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A <tt>ModularRealmAuthenticator</tt> is an {@link org.jsecurity.authc.Authenticator Authenticator}
 * that delgates account lookups to a pluggable (modular) collection of
 * {@link Realm}s.  This enables PAM (Pluggable Authentication Module) behavior in JSecurity
 * for authentication.  For all intents and purposes, a JSecurity Realm can be thought of a PAM 'module'.
 *
 * <p>Using this Authenticator allows you to &quot;plug-in&quot; your own
 * <tt>Realm</tt>s as you see fit.  Common realms are those based on accessing
 * LDAP, relational databases, file systems, etc.
 *
 * <p>If only one realm is configured (this is often the case for most applications), authentication success is naturally
 * only dependent upon invoking this one Realm's
 * {@link Realm#getAccount(org.jsecurity.authc.AuthenticationToken) getAccount} method (i.e.
 * a null return value means no account could be found, or an AuthenticationException could be thrown, which would be
 * propagated to the caller, etc - see the JavaDoc for more details).
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
 * {@link org.jsecurity.authc.support.AllSuccessfulModularAuthenticationStrategy AllSuccessfulModularAuthenticationStrategy}
 *
 * @see #setRealms
 * @see AllSuccessfulModularAuthenticationStrategy
 * @see AtLeastOneSuccessfulModularAuthenticationStrategy
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
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

    protected ModularAuthenticationStrategy modularAuthenticationStrategy;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public ModularRealmAuthenticator() {
    }

    public ModularRealmAuthenticator( Realm realm ) {
        setRealm( realm );
        init();
    }

    public ModularRealmAuthenticator( List<Realm> realms ) {
        setRealms( realms );
        init();
    }

    protected ModularAuthenticationStrategy createModularAuthenticationStrategy() {
        return new AllSuccessfulModularAuthenticationStrategy();
    }

    protected void ensureModudularAuthenticationStrategy() {
        ModularAuthenticationStrategy strategy = getModularAuthenticationStrategy();
        if ( strategy == null ) {
            strategy = createModularAuthenticationStrategy();
            setModularAuthenticationStrategy(strategy);
        }
    }

    protected void afterModularAuthenticationStrategySet(){}

    protected void afterAuthenticationEventFactorySet() {
        ensureModudularAuthenticationStrategy();
        afterModularAuthenticationStrategySet();
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Convenience setter for single-realm environments (fairly common).  This method just wraps the realm in a
     * collection and then calls {@link #setRealms}.
     * @param realm the realm to consult during authentication attempts.
     */
    public void setRealm( Realm realm ) {
        List<Realm> realms = new ArrayList<Realm>(1);
        realms.add( realm );
        setRealms( realms );
    }

    /**
     * Sets all realms used by this Authenticator, providing PAM (Pluggable Authentication Module) configuration.
     * @param realms the realms to consult during authentication attempts.
     */
    public void setRealms( Collection<Realm> realms ) {
        this.realms = realms;
    }

    /**
     * Returns the <tt>ModularAuthenticationStrategy</tt> utilized by this modular authenticator during a multi-realm
     * log-in attempt.  This object is only used when two or more Realms are configured.
     *
     * <p>Unless overridden by
     * the {@link #setModularAuthenticationStrategy(ModularAuthenticationStrategy)} method, the default implementation
     * is the {@link org.jsecurity.authc.support.AllSuccessfulModularAuthenticationStrategy}.
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
    public void setModularAuthenticationStrategy( ModularAuthenticationStrategy modularAuthenticationStrategy ) {
        this.modularAuthenticationStrategy = modularAuthenticationStrategy;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Creates an <tt>AggregateAccount</tt> instance that will be used to aggregate account data across
     * all successfully consulted Realms during a multi-realm log-in attempt.
     *
     * <p>It is primarily provided for subclass overriding behavior if necessary - the default implementation only
     * returns <tt>new {@link SimpleAccount SimpleAccount}();</tt>, which implements the <tt>AggregateAccount</tt> interface.
     *
     * @param token the authentication token submitted during the authentication process which may be useful
     * to subclasses in constructing the returned <tt>Account</tt> instance.
     * @return an <tt>AggregateAccount</tt> instance that will be used to aggregate all
     * <tt>Account</tt> objects returned by all configured <tt>Realm</tt>s.
     */
    protected AggregateAccount createAggregateAccount( AuthenticationToken token ) {
        return new SimpleAccount();
    }

    /**
     * Used by the internal {@link #doAuthenticate} implementation to ensure that the <tt>realms</tt> property
     * has been set.  The default implementation ensures the property is not null and not empty.
     * @throws IllegalStateException if the <tt>realms</tt> property is configured incorrectly.
     */
    protected void assertRealmsConfigured() throws IllegalStateException {
        if ( realms == null || realms.isEmpty() ) {
            String msg = "No realms configured for this ModularRealmAuthenticator.  Configuration error.";
            throw new IllegalStateException( msg );
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
    protected Account doSingleRealmAuthentication( Realm realm, AuthenticationToken token ) {
        if ( !realm.supports( token ) ) {
            String msg = "Single configured realm [" + realm + "] does not support authentication token [" +
                token + "].  Please ensure that the appropriate Realm implementation is " +
                "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException( msg );
        }
        Account account = realm.getAccount( token );
        if ( account == null ) {
            String msg = "Single configured realm [" + realm + "] was unable to find account data for the " +
                "submitted AuthenticationToken [" + token + "].";
            throw new UnknownAccountException( msg );
        }
        return account;
    }

    /**
     * Performs the multi-realm authentication attempt by calling back to a {@link ModularAuthenticationStrategy} object
     * as each realm is consulted for <tt>Account</tt> for the specified <tt>token</tt>.
     *
     * @param realms the multiple realms configured on this Authenticator instance.
     * @param token the submitted AuthenticationToken representing the subject's (user's) log-in principals and credentials.
     * @return an aggregated Account instance representing account data across all the successfully
     * consulted realms.
     */
    protected Account doMultiRealmAuthentication( Collection<? extends Realm> realms, AuthenticationToken token ) {

        ModularAuthenticationStrategy strategy = getModularAuthenticationStrategy();

        strategy.beforeAllAttempts( realms, token );
        
        AggregateAccount aggregateAccount = createAggregateAccount( token );

        if (log.isDebugEnabled()) {
            log.debug("Iterating through [" + realms.size() + "] realms for PAM authentication");
        }

        for( Realm realm : realms) {

            strategy.beforeAttempt( realm, token );

            if( realm.supports( token ) ) {

                if (log.isDebugEnabled()) {
                    log.debug("Attempting to authenticate token [" + token + "] " +
                        "using realm of type [" + realm.getClass() + "]");
                }

                Account account = null;
                Throwable t = null;
                try {
                    account = realm.getAccount( token );
                } catch ( Throwable throwable ) {
                    t = throwable;
                    if ( log.isTraceEnabled() ) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.trace( msg, t );
                    }
                }

                strategy.afterAttempt( realm, token, account, t );

                // If non-null account is returned, then the realm was able to authenticate the
                // user - so merge the account with any accumulated before:
                if( account != null ) {

                    if (log.isDebugEnabled()) {
                        log.debug("Account successfully authenticated using realm of type [" +
                            realm.getClass().getName() + "]");
                    }

                    aggregateAccount.merge( account );
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Realm of type [" + realm.getClass().getName() + "] does not support token " +
                            "[" + token + "].  Skipping realm." );
                }
            }
        }

        strategy.afterAllAttempts( token, aggregateAccount );

        return aggregateAccount;
    }


    /**
     * <p>Attempts to authenticate the given token by iterating over the internal collection of
     * {@link Realm}s.  For each realm, first the {@link Realm#supports(org.jsecurity.authc.AuthenticationToken)}
     * method will be called to determine if the realm supports the <tt>authenticationToken</tt> method argument.
     *
     * If a realm does support
     * the token, its {@link Realm#getAccount(org.jsecurity.authc.AuthenticationToken)}
     * method will be called.  If the realm returns a non-null account, the token will be
     * considered authenticated and the account data recorded.  If the realm returns <tt>null</tt>, the next
     * realm will be consulted.  If no realms support the token or all supported realms return null,
     * an {@link AuthenticationException} will be thrown to indicate that the user could not be authenticated.
     *
     * <p>After all realms have been consulted, the information from each realm is aggregated into a single
     * {@link org.jsecurity.authc.Account} object and returned.
     *
     * @param authenticationToken the token containing the authentication principal and credentials for the
     * user being authenticated.
     * @return account information attributed to the authenticated user.
     * @throws AuthenticationException if the user could not be authenticated or the user is denied authentication
     * for the given principal and credentials.
     */
    protected Account doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {

        assertRealmsConfigured();

        if ( realms.size() == 1 ) {
            return doSingleRealmAuthentication( realms.iterator().next(), authenticationToken );
        } else {
            return doMultiRealmAuthentication( realms, authenticationToken );
        }
    }
}