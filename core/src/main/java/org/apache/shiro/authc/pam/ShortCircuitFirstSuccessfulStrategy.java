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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Collection;

/**
 * {@link AuthenticationStrategy} implementation that extends  {@link FirstSuccessfulStrategy} to 
 * send {@link ShortCircuitIterationException} before attempting authentication with subsequent 
 * reamls after a first successfully consulted Realm .
 *
 * @see AtLeastOneSuccessfulStrategy AtLeastOneSuccessfulAuthenticationStrategy FirstSuccessfulStrategy
 * @since 1.4.1
 */
public class ShortCircuitFirstSuccessfulStrategy extends FirstSuccessfulStrategy {


    /**
     * Throws ShortCircuitIterationException if authentication is successful with a previously 
     * consulted realm. Returns the <code>aggregate</code> method argument, without modification
     * otherwise.
     */
    public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        if (aggregate != null && isEmpty(aggregate.getPrincipals())) {
            throw new ShortCircuitIterationException();
        }
        return aggregate;
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }

}
