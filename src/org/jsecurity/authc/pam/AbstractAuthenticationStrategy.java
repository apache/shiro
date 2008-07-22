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

import java.util.Collection;

/**
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractAuthenticationStrategy implements ModularAuthenticationStrategy {

    protected transient final Log log = LogFactory.getLog(getClass());

    public AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException {
        return new SimpleAuthenticationInfo();
    }

    public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        return aggregate;
    }

    public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t) throws AuthenticationException {
        AuthenticationInfo info;
        if (singleRealmInfo == null) {
            info = aggregateInfo;
        } else {
            if (aggregateInfo == null) {
                info = singleRealmInfo;
            } else {
                info = merge(singleRealmInfo, aggregateInfo);
            }
        }

        return info;
    }

    protected AuthenticationInfo merge(AuthenticationInfo info, AuthenticationInfo aggregate) {
        if( aggregate instanceof MergableAuthenticationInfo ) {
            ((MergableAuthenticationInfo)aggregate).merge(info);
            return aggregate;
        } else {
            throw new IllegalArgumentException( "Attempt to merge authentication info from multiple realms, but aggreagate " +
                      "AuthenticationInfo is not of type MergableAuthenticationInfo." );
        }
    }

    public AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        return aggregate;
    }
}
