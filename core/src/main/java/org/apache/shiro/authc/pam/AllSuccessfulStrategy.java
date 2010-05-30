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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.realm.Realm;


/**
 * <tt>AuthenticationStrategy</tt> implementation that requires <em>all</em> configured realms to
 * <b>successfully</b> process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 * <p/>
 * <p>If one or more realms do not support the submitted token, or one or more are unable to acquire
 * <tt>AuthenticationInfo</tt> for the token, this implementation will immediately fail the log-in attempt for the
 * associated subject (user).
 *
 * @since 0.2
 */
public class AllSuccessfulStrategy extends AbstractAuthenticationStrategy {

    /** Private class log instance. */
    private static final Logger log = LoggerFactory.getLogger(AllSuccessfulStrategy.class);

    /**
     * Because all realms in this strategy must complete successfully, this implementation ensures that the given
     * <code>Realm</code> {@link org.apache.shiro.realm.Realm#supports(org.apache.shiro.authc.AuthenticationToken) supports} the given
     * <code>token</code> argument.  If it does not, this method throws an
     * {@link UnsupportedTokenException UnsupportedTokenException} to end the authentication
     * process immediately. If the realm does support the token, the <code>info</code> argument is returned immediately.
     */
    public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        if (!realm.supports(token)) {
            String msg = "Realm [" + realm + "] of type [" + realm.getClass().getName() + "] does not support " +
                    " the submitted AuthenticationToken [" + token + "].  The [" + getClass().getName() +
                    "] implementation requires all configured realm(s) to support and be able to process the submitted " +
                    "AuthenticationToken.";
            throw new UnsupportedTokenException(msg);
        }

        return info;
    }

    /**
     * Merges the specified <code>info</code> into the <code>aggregate</code> argument and returns it (just as the
     * parent implementation does), but additionally ensures the following:
     * <ol>
     * <li>if the <code>Throwable</code> argument is not <code>null</code>, re-throws it to immediately cancel the
     * authentication process, since this strategy requires all realms to authenticate successfully.</li>
     * <li>neither the <code>info</code> or <code>aggregate</code> argument is <code>null</code> to ensure that each
     * realm did in fact authenticate successfully</li>
     * </ol>
     */
    public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo info, AuthenticationInfo aggregate, Throwable t)
            throws AuthenticationException {
        if (t != null) {
            if (t instanceof AuthenticationException) {
                //propagate:
                throw ((AuthenticationException) t);
            } else {
                String msg = "Unable to acquire account data from realm [" + realm + "].  The [" +
                        getClass().getName() + " implementation requires all configured realm(s) to operate successfully " +
                        "for a successful authentication.";
                throw new AuthenticationException(msg, t);
            }
        }
        if (info == null) {
            String msg = "Realm [" + realm + "] could not find any associated account data for the submitted " +
                    "AuthenticationToken [" + token + "].  The [" + getClass().getName() + "] implementation requires " +
                    "all configured realm(s) to acquire valid account data for a submitted token during the " +
                    "log-in process.";
            throw new UnknownAccountException(msg);
        }

        log.debug("Account successfully authenticated using realm [{}]", realm);

        // If non-null account is returned, then the realm was able to authenticate the
        // user - so merge the account with any accumulated before:
        merge(info, aggregate);

        return aggregate;
    }
}
