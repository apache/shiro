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
package org.apache.shiro.realm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class AuthenticatingRealmJavaTest {

    @Test
    @DisplayName("should create Argon2 hash when user does not exist")
    void authenticatingRealmShouldCreateArgonHashWhenUserDoesNotExist() {
        // given
        CredentialsMatcher matcher = new PasswordMatcher();
        CredentialsMatcher passwordMatcher = Mockito.spy(matcher);
        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);
        NullAuthenticatingRealm spiedRealm = Mockito.spy(realm);

        // when
        var info = spiedRealm.getAuthenticationInfo(token);

        // then
        assertThat(info).isNull();
        Mockito.verify(passwordMatcher, times(1)).createSimulatedCredentials();

        Object simulatedCredentials = spiedRealm.authInfo.getCredentials();
        assertThat(simulatedCredentials).isInstanceOf(Hash.class);
        assertThat(simulatedCredentials.getClass().getName()).contains("Argon");
    }

    @Test
    @DisplayName("should create BCrypt hash when user does not exist")
    void authenticatingRealmShouldCreateBcryptHashWhenUserDoesNotExist() {
        // given
        DefaultHashService bcryptHashService = new DefaultHashService();
        bcryptHashService.setDefaultAlgorithmName("2y");
        DefaultPasswordService defaultPasswordService = new DefaultPasswordService();
        defaultPasswordService.setHashService(bcryptHashService);
        PasswordMatcher matcher = new PasswordMatcher();
        matcher.setPasswordService(defaultPasswordService);

        CredentialsMatcher passwordMatcher = Mockito.spy(matcher);
        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);
        NullAuthenticatingRealm spiedRealm = Mockito.spy(realm);

        // when
        var info = spiedRealm.getAuthenticationInfo(token);

        // then
        assertThat(info).isNull();
        Mockito.verify(passwordMatcher, times(1)).createSimulatedCredentials();

        Object simulatedCredentials = spiedRealm.authInfo.getCredentials();
        assertThat(simulatedCredentials).isInstanceOf(Hash.class);
        assertThat(simulatedCredentials.getClass().getName())
                .matches(name -> name.contains("Argon") || name.contains("BCrypt"));
    }

    /**
     * For the test, it is important that this class returns {@code null} for
     * {@link AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)},
     * so that simulatedAuthenticationInfo is being created.
     */
    static class NullAuthenticatingRealm extends AuthenticatingRealm {

        /**
         * captured created authenticationInfo
         */
        private AuthenticationInfo authInfo;

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
            return null;
        }

        /**
         * Captures the created authenticationInfo for tests.
         * @return see super method.
         */
        @Override
        AuthenticationInfo ensureSimulatedAuthenticationInfo() {
            final var authInfo1 = super.ensureSimulatedAuthenticationInfo();
            this.authInfo = authInfo1;
            return authInfo1;
        }
    }
}
