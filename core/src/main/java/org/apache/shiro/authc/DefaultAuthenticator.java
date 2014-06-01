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
package org.apache.shiro.authc;

import org.apache.shiro.account.Account;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authc.strategy.AuthenticationStrategy;
import org.apache.shiro.authc.strategy.DefaultAuthenticationAttempt;
import org.apache.shiro.authc.strategy.FirstRealmSuccessfulStrategy;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.EventBusAware;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.Assert;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;

/**
 * @since 2.0
 */
public class DefaultAuthenticator implements Authenticator, EventBusAware {

    private static final Logger log = LoggerFactory.getLogger(DefaultAuthenticator.class);

    private Collection<Realm> realms;

    private EventBus eventBus;

    private AuthenticationStrategy authenticationStrategy;

    public DefaultAuthenticator(){
        //default in Shiro 2.0 is 'first successful'. This is the desired behavior for most Shiro users (80/20 rule).
        // < 2.0 was 'at least one successful', which was often not desired and caused unnecessary I/O.
        this.authenticationStrategy = new FirstRealmSuccessfulStrategy();
    }

    public Collection<Realm> getRealms() {
        return realms;
    }

    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    public EventBus getEventBus() {
        return eventBus;
    }

    public void setEventBus(EventBus eventBus) {
        this.eventBus = eventBus;
    }

    public AuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    public void setAuthenticationStrategy(AuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    @Deprecated
    public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        throw new UnsupportedOperationException("The " + getClass().getName() + " implementation does not support " +
                "legacy (pre 2.0) authentication behavior.  Invoke 'authenticateAccount' instead.");
    }

    protected Account authenticateSingleRealmAccount(Realm realm, AuthenticationToken token) throws Throwable {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] does not support authentication token [" +
                    token + "].  Please ensure that the appropriate Realm implementation is " +
                    "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
        }
        return realm.authenticateAccount(token);
    }

    protected Account authenticateMultiRealmAccount(Collection<Realm> realms, AuthenticationToken token) throws Throwable {
        DefaultAuthenticationAttempt attempt =
                new DefaultAuthenticationAttempt(token, Collections.unmodifiableCollection(realms));
        return getAuthenticationStrategy().execute(attempt);
    }

    public Account authenticateAccount(AuthenticationToken token) throws AuthenticationException {

        Assert.notNull(token, "AuthenticationToken argument cannot be null.");

        log.trace("Authentication submission received for authentication token [{}]", token);

        Account account;
        try {
            account = doAuthenticateAccount(token);
            if (account == null) {
                String msg = "No account returned by any configured realms for submitted authentication token ["
                        + token + "].";
                throw new UnknownAccountException(msg);
            }
        } catch (Throwable t) {
            AuthenticationException ae = null;
            if (t instanceof AuthenticationException) {
                ae = (AuthenticationException) t;
            }
            if (ae == null) {
                //Exception thrown was not an expected AuthenticationException.  Therefore it is probably a little more
                //severe or unexpected.  So, wrap in an AuthenticationException, log to warn, and propagate:
                String msg = "Authentication failed for submitted token [" + token + "].  Possible unexpected " +
                        "error? (Typical or expected login exceptions should extend from AuthenticationException).";
                ae = new AuthenticationException(msg, t);
            }
            try {
                notifyFailure(token, ae);
            } catch (Throwable t2) {
                if (log.isWarnEnabled()) {
                    String msg = "Unable to send notification for failed authentication attempt - listener error?.  " +
                            "Please check your EventBus implementation.  Logging 'send' exception " +
                            "and propagating original AuthenticationException instead...";
                    log.warn(msg, t2);
                }
            }

            throw ae;
        }

        log.debug("Authentication successful for submitted authentication token [{}].  Returned account [{}]",
                token, account);

        notifySuccess(token, account);

        return account;
    }

    protected Account doAuthenticateAccount(AuthenticationToken token) throws Throwable {
        Collection<Realm> realms = getRealms();
        int size = CollectionUtils.size(realms);
        Assert.isTrue(size > 0, "One or more realms must be configured to perform authentication.");

        if (size == 1) {
            return authenticateSingleRealmAccount(realms.iterator().next(), token);
        }
        return authenticateMultiRealmAccount(realms, token);
    }

    protected void notifySuccess(AuthenticationToken token, Account account) {
        EventBus eventBus = getEventBus();
        if (eventBus != null) {
            SuccessfulAuthenticationEvent event = new SuccessfulAuthenticationEvent(this, token, account);
            eventBus.publish(event);
        }
    }

    protected void notifyFailure(AuthenticationToken token, Throwable t) {
        EventBus eventBus = getEventBus();
        if (eventBus != null) {
            FailedAuthenticationEvent event = new FailedAuthenticationEvent(this, token, t);
            eventBus.publish(event);
        }
    }
}
