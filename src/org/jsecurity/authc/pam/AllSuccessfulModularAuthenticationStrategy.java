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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.*;
import org.jsecurity.realm.Realm;

/**
 * <tt>ModularAuthenticationStrategy</tt> implementation that requires <em>all</em> configured realms to
 * <b>successfully</b> process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 *
 * <p>If one or more realms do not support the submitted token, or one or more are unable to acquire
 * <tt>AuthenticationInfo</tt> for the token, this implementation will immediately fail the log-in attempt for the
 * associated subject (user).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class AllSuccessfulModularAuthenticationStrategy extends AbstractAuthenticationStrategy {

    private static final Log log = LogFactory.getLog(AllSuccessfulModularAuthenticationStrategy.class);    

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

        // If non-null account is returned, then the realm was able to authenticate the
        // user - so merge the account with any accumulated before:
        if (log.isDebugEnabled()) {
            log.debug("Account successfully authenticated using realm of type [" + realm.getClass().getName() + "]");
        }

        if( aggregate instanceof MergableAuthenticationInfo ) {
            ((MergableAuthenticationInfo)aggregate).merge(info);
            return aggregate;
        } else {
            throw new IllegalArgumentException( "Attempt to merge authentication info from multiple realms, but aggreagate " +
                      "AuthenticationInfo is not of type MergableAuthenticationInfo." );
        }
    }
}
