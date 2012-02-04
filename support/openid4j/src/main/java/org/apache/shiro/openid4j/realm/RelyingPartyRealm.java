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
package org.apache.shiro.openid4j.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.openid4j.OpenIdService;
import org.apache.shiro.realm.AuthenticatingRealm;

/**
 * A {@code Realm} implementation that performs OpenID authentication by acting as the &quot;Relying Party&quot;
 * (client) to an OpenId Provider (server).
 *
 * @since 1.2
 */
public class RelyingPartyRealm extends AuthenticatingRealm {

    private OpenIdService openIdService;

    public RelyingPartyRealm() {

    }

    public OpenIdService getOpenIdService() {
        return openIdService;
    }

    public void setOpenIdService(OpenIdService openIdService) {
        this.openIdService = openIdService;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        //TODO

        return null;

    }
}
