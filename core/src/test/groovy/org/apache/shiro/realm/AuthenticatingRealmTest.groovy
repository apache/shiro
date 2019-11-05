/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm

import org.apache.shiro.authc.credential.CredentialsMatcher
import org.apache.shiro.cache.Cache
import org.apache.shiro.cache.CacheManager
import org.apache.shiro.subject.PrincipalCollection
import org.apache.shiro.authc.*
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link AuthenticatingRealm} implementation.
 */
class AuthenticatingRealmTest {

    @Test
    void testSetName() {
        AuthenticatingRealm realm = new TestAuthenticatingRealm()
        def name = "foo"

        realm.name = name
        realm.init()

        assertEquals name, realm.name
        assertEquals name + AuthenticatingRealm.DEFAULT_AUTHENTICATION_CACHE_SUFFIX, realm.authenticationCacheName

        realm.authenticationCacheName = "bar"

        assertEquals name, realm.name
        assertEquals "bar", realm.authenticationCacheName
    }

    @Test
    void testSupports() {
        def password = "foo"
        def token = new UsernamePasswordToken("username", password);

        AuthenticatingRealm realm = new TestAuthenticatingRealm();

        assertTrue realm.supports(token)
    }

    @Test
    void testSupportsWithCustomAuthenticationTokenClass() {

        def token = createStrictMock(RememberMeAuthenticationToken)

        replay token

        AuthenticatingRealm realm = new TestAuthenticatingRealm();
        realm.setAuthenticationTokenClass RememberMeAuthenticationToken

        assertTrue realm.supports(token)

        verify token
    }

    @Test
    void testNewInstanceWithCacheManager() {
        def cacheManager = createStrictMock(CacheManager)

        replay cacheManager

        AuthenticatingRealm realm = new TestAuthenticatingRealm(cacheManager)

        assertSame cacheManager, realm.cacheManager

        verify cacheManager
    }

    @Test
    void testNewInstanceWithCredentialsMatcher() {
        def matcher = createStrictMock(CredentialsMatcher)

        replay matcher

        AuthenticatingRealm realm = new TestAuthenticatingRealm(matcher)
        assertSame matcher, realm.credentialsMatcher

        verify matcher
    }

    @Test
    void testSetCache() {
        def cache = createStrictMock(Cache)

        replay cache

        AuthenticatingRealm realm = new TestAuthenticatingRealm()
        realm.authenticationCache = cache

        assertSame cache, realm.authenticationCache

        verify cache
    }

    @Test
    void testGetAuthenticationInfo() {

        def password = "foo"
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        expect(token.getCredentials()).andReturn(password).anyTimes();
        expect(info.getCredentials()).andReturn(password).anyTimes();

        replay token, info

        AuthenticatingRealm realm = new TestAuthenticatingRealm()
        realm.info = info

        def returnedInfo = realm.getAuthenticationInfo(token)

        assertSame returnedInfo, info

        verify token, info
    }

    @Test
    void testGetAuthenticationInfoWithNullReturnValue() {

        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        replay token, info

        AuthenticatingRealm realm = new TestAuthenticatingRealm()

        def returnedInfo = realm.getAuthenticationInfo(token)

        assertNull returnedInfo

        verify token, info
    }

    @Test
    void testAuthenticationCachingEnabledWithCacheMiss() {

        def username = "foo"
        def password = "bar"

        def cacheManager = createStrictMock(CacheManager)
        def cache = createStrictMock(Cache)
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        expect(cacheManager.getCache(isA(String))).andReturn cache
        expect(token.getPrincipal()).andReturn(username).anyTimes()
        expect(token.getCredentials()).andReturn(password).anyTimes()

        expect(cache.get(eq(username))).andReturn null
        expect(cache.put(eq(username), same(info))).andReturn null

        expect(info.getCredentials()).andReturn(password)

        replay cacheManager, cache, token, info

        AuthenticatingRealm realm = new TestAuthenticatingRealm()
        realm.info = info

        realm.cacheManager = cacheManager
        realm.authenticationCachingEnabled = true

        def returnedInfo = realm.getAuthenticationInfo(token)

        assertSame info, returnedInfo

        verify cacheManager, cache, token, info
    }

    @Test
    void testAuthenticationCachingEnabledWithCacheHit() {

        def username = "foo"
        def password = "bar"

        def cacheManager = createStrictMock(CacheManager)
        def cache = createStrictMock(Cache)
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        expect(cacheManager.getCache(isA(String))).andReturn cache
        expect(token.getPrincipal()).andReturn(username).anyTimes()
        expect(token.getCredentials()).andReturn(password).anyTimes()

        expect(cache.get(eq(username))).andReturn info

        expect(info.getCredentials()).andReturn(password)

        replay cacheManager, cache, token, info

        AuthenticatingRealm realm = new NoLookupAuthenticatingRealm()
        realm.cacheManager = cacheManager
        realm.authenticationCachingEnabled = true

        def returnedInfo = realm.getAuthenticationInfo(token)

        assertSame info, returnedInfo

        verify cacheManager, cache, token, info
    }

    @Test
    void testLogoutWithAuthenticationCachingEnabled() {

        def realmName = "testRealm"
        def authcCacheName = realmName + AuthenticatingRealm.DEFAULT_AUTHENTICATION_CACHE_SUFFIX
        def username = "foo"

        def cacheManager = createStrictMock(CacheManager)
        def cache = createStrictMock(Cache)
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)
        def principals = createStrictMock(PrincipalCollection)
        def realmPrincipals = [username]

        expect(principals.isEmpty()).andReturn(false).anyTimes()
        expect(principals.fromRealm(eq(realmName))).andReturn realmPrincipals

        expect(cacheManager.getCache(eq(authcCacheName))).andReturn cache
        expect(cache.remove(eq(username))).andReturn info

        replay cacheManager, cache, token, info, principals

        AuthenticatingRealm realm = new NoLookupAuthenticatingRealm()
        realm.cacheManager = cacheManager
        realm.authenticationCachingEnabled = true
        realm.name = realmName

        realm.onLogout(principals)

        verify cacheManager, cache, token, info, principals
    }

    @Test
    void testAssertCredentialsMatchWithNullCredentialsMatcher() {
        AuthenticatingRealm realm = new TestAuthenticatingRealm();
        realm.credentialsMatcher = null

        try {
            realm.assertCredentialsMatch(null, null)
            fail("should have thrown an AuthenticationException")
        } catch (AuthenticationException e) {
            assertNotNull e.getMessage()
            assertTrue e.getMessage().contains("A CredentialsMatcher must be configured")
        }
    }

    @Test
    void testAssertCredentialsMatchFailure() {

        def matcher = createStrictMock(CredentialsMatcher)
        def token = createStrictMock(AuthenticationToken)
        def info = createStrictMock(AuthenticationInfo)

        expect(matcher.doCredentialsMatch(same(token), same(info))).andReturn false

        replay matcher, token, info

        AuthenticatingRealm realm = new TestAuthenticatingRealm()
        realm.credentialsMatcher = matcher
        try {
            realm.assertCredentialsMatch(token, info)
            fail("IncorrectCredentialsException should have been thrown.");
        } catch (IncorrectCredentialsException expected) {
        }

        verify matcher, token, info
    }


    private class TestAuthenticatingRealm extends AuthenticatingRealm {

        def AuthenticationInfo info;

        def TestAuthenticatingRealm() {
            super()
        }

        def TestAuthenticatingRealm(CacheManager cacheManager) {
            super(cacheManager)
        }

        def TestAuthenticatingRealm(CredentialsMatcher matcher) {
            super(matcher)
        }

        def TestAuthenticatingRealm(CacheManager cacheManager, CredentialsMatcher matcher) {
            super(cacheManager, matcher)
        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
            return info;
        }
    }

    private class NoLookupAuthenticatingRealm extends AuthenticatingRealm {
        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
            fail("This implementation does not allow lookups.");
            return null;
        }
    }

}
