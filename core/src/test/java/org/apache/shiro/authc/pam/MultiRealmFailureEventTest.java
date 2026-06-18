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

import org.apache.shiro.authc.AbstractAuthenticator;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.event.Subscribe;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class MultiRealmFailureEventTest extends AuthenticatingRealm {
    private boolean eventReceived;

    @Test
    public void realmFailureEvent() {
        var securityManager = new DefaultSecurityManager();
        securityManager.setRealms(List.of(this, this));
        securityManager.getEventBus().register(this);
        if (securityManager.getAuthenticator() instanceof AbstractAuthenticator authenticator) {
            authenticator.setEventBus(securityManager.getEventBus());
        }
        var subject = new Subject.Builder(securityManager).buildSubject();
        assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(() -> subject.login(new UsernamePasswordToken("user", "password")));
        assertThat(eventReceived).isTrue();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        throw new IllegalStateException("Realm failure");
    }

    @Subscribe
    public void handleAuthenticationException(AuthenticationExceptionEvent event) {
        eventReceived = true;
    }
}
