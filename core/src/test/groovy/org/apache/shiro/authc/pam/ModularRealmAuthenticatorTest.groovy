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
package org.apache.shiro.authc.pam

import org.apache.shiro.realm.Realm
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.authc.*
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link ModularRealmAuthenticator} implementation.
 *
 * @since 1.2
 */
class ModularRealmAuthenticatorTest {

    @Test
    void testNewInstance() {
        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        assertNotNull mra.authenticationStrategy
        assertTrue mra.authenticationStrategy instanceof AtLeastOneSuccessfulStrategy
    }

    @Test
    void testDoAuthenticateNoRealms() {

        def token = createStrictMock(AuthenticationToken)

        replay token

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator();
        try {
            mra.doAuthenticate(token)
            fail "ModularRealmAuthenticator should fail when no realms are configured."
        } catch (IllegalStateException expected) {
        }

        verify token
    }

    @Test
    void testSingleRealmAuthenticationSuccess() {

        def realm = createStrictMock(Realm)
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        expect(realm.supports(same(token))).andReturn true
        expect(realm.getAuthenticationInfo(same(token))).andReturn info

        replay realm, token, info

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.realms = [realm]

        assertSame info, mra.doAuthenticate(token)

        verify realm, token, info
    }

    @Test
    void testSingleRealmAuthenticationWithUnsupportedToken() {

        def realm = createStrictMock(Realm)
        def token = createStrictMock(AuthenticationToken)

        expect(realm.supports(same(token))).andReturn false

        replay realm, token

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.realms = [realm]

        try {
            mra.doAuthenticate(token)
            fail "Should throw UnsupportedTokenException when single realm does not support a token."
        } catch (UnsupportedTokenException expected) {
        }

        verify realm, token
    }

    @Test
    void testSingleRealmAuthenticationWithNullAuthenticationInfo() {

        def realm = createStrictMock(Realm)
        def token = createStrictMock(AuthenticationToken)

        expect(realm.supports(same(token))).andReturn true
        expect(realm.getAuthenticationInfo(same(token))).andReturn null

        replay realm, token

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.realms = [realm]

        try {
            mra.doAuthenticate(token)
            fail "Should throw UnknownAccountException when single realm returns null."
        } catch (UnknownAccountException expected) {
        }

        verify realm, token
    }

    @Test
    void testMultiRealmAuthenticationSuccess() {

        def realm1 = createStrictMock(Realm)
        def realm1Info = createStrictMock(AuthenticationInfo)
        def realm2 = createStrictMock(Realm)
        def realm2Info = createStrictMock(AuthenticationInfo)
        def token = createStrictMock(AuthenticationToken)
        def aggregate = createStrictMock(AuthenticationInfo)
        def strategy = createStrictMock(AuthenticationStrategy)
        def realms = [realm1, realm2]


        expect(strategy.beforeAllAttempts(same(realms), same(token))).andReturn aggregate

        expect(strategy.beforeAttempt(same(realm1), same(token), same(aggregate))).andReturn aggregate
        expect(realm1.supports(same(token))).andReturn true
        expect(realm1.getAuthenticationInfo(same(token))).andReturn realm1Info
        expect(strategy.afterAttempt(same(realm1), same(token), same(realm1Info), same(aggregate), isNull(Throwable))).andReturn aggregate

        expect(strategy.beforeAttempt(same(realm2), same(token), same(aggregate))).andReturn aggregate
        expect(realm2.supports(same(token))).andReturn true
        expect(realm2.getAuthenticationInfo(same(token))).andReturn realm2Info
        expect(strategy.afterAttempt(same(realm2), same(token), same(realm2Info), same(aggregate), isNull(Throwable))).andReturn aggregate

        expect(strategy.afterAllAttempts(same(token), same(aggregate))).andReturn aggregate


        replay realm1, realm1Info, realm2, realm2Info, token, aggregate, strategy

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.authenticationStrategy = strategy
        mra.realms = realms

        assertSame aggregate, mra.doAuthenticate(token)

        verify realm1, realm1Info, realm2, realm2Info, token, aggregate, strategy
    }

    @Test
    void testMultiRealmAuthenticationWithAuthenticationException() {

        def realm1 = createStrictMock(Realm)
        def realm1Info = createStrictMock(AuthenticationInfo)
        def realm2 = createStrictMock(Realm)
        def token = createStrictMock(AuthenticationToken)
        def aggregate = createStrictMock(AuthenticationInfo)
        def strategy = createStrictMock(AuthenticationStrategy)
        def authcException = new AuthenticationException("test")
        def realms = [realm1, realm2]


        expect(strategy.beforeAllAttempts(same(realms), same(token))).andReturn aggregate

        expect(strategy.beforeAttempt(same(realm1), same(token), same(aggregate))).andReturn aggregate
        expect(realm1.supports(same(token))).andReturn true
        expect(realm1.getAuthenticationInfo(same(token))).andReturn realm1Info
        expect(strategy.afterAttempt(same(realm1), same(token), same(realm1Info), same(aggregate), isNull(Throwable))).andReturn aggregate

        expect(strategy.beforeAttempt(same(realm2), same(token), same(aggregate))).andReturn aggregate
        expect(realm2.supports(same(token))).andReturn true
        expect(realm2.getAuthenticationInfo(same(token))).andThrow authcException
        expect(strategy.afterAttempt(same(realm2), same(token), isNull(AuthenticationInfo), same(aggregate), same(authcException))).andReturn aggregate

        expect(strategy.afterAllAttempts(same(token), same(aggregate))).andReturn aggregate


        replay realm1, realm1Info, realm2, token, aggregate, strategy

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.authenticationStrategy = strategy
        mra.realms = realms

        assertSame aggregate, mra.doAuthenticate(token)

        verify realm1, realm1Info, realm2, token, aggregate, strategy
    }

    @Test
    void testOnLogout() {

        def realm = createStrictMock(LogoutAwareRealm)
        def principals = createStrictMock(PrincipalCollection)

        realm.onLogout(same(principals))

        replay realm, principals

        ModularRealmAuthenticator mra = new ModularRealmAuthenticator()
        mra.realms = [realm]
        mra.onLogout(principals)

        verify realm, principals
    }

    private static interface LogoutAwareRealm extends Realm, LogoutAware {

    }
}
