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

import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.cache.Cache
import org.apache.shiro.cache.CacheManager
import org.apache.shiro.subject.PrincipalCollection
import org.junit.Test
import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link CachingRealm} implementation.
 */
class CachingRealmTest {

    @Test
    void testCachingEnabled() {

        CachingRealm realm = new TestCachingRealm()

        assertTrue realm.cachingEnabled
        realm.cachingEnabled = false
        assertFalse realm.cachingEnabled
    }

    @Test
    void testSetName() {

        CachingRealm realm = new TestCachingRealm()

        assertTrue realm.name.contains(TestCachingRealm.class.getName())

        realm.name = "testRealm"
        assertEquals "testRealm", realm.name
    }


    @Test
    void testNewInstanceWithCacheManager() {

        def cacheManager = createStrictMock(CacheManager)

        CachingRealm realm = new TestCachingRealm()
        realm.cacheManager = cacheManager

        assertNotNull realm.cacheManager
        assertTrue realm.templateMethodCalled
    }

    @Test
    void testOnLogout() {

        def realmName = "testRealm"

        def cacheManager = createStrictMock(CacheManager)
        def cache = createStrictMock(Cache)
        def principals = createStrictMock(PrincipalCollection)

        expect(principals.isEmpty()).andReturn(false).anyTimes()

        replay cacheManager, cache, principals

        CachingRealm realm = new TestCachingRealm()

        realm.cacheManager = cacheManager
        realm.name = realmName

        realm.onLogout(principals)

        assertTrue realm.doClearCacheCalled

        verify cacheManager, cache, principals
    }

    @Test
    void testGetAvailablePrincipalWithRealmPrincipals() {

        def realmName = "testRealm"
        def username = "foo"

        def principals = createStrictMock(PrincipalCollection)

        expect(principals.isEmpty()).andReturn false
        expect(principals.fromRealm(eq(realmName))).andReturn([username])

        replay principals

        CachingRealm realm = new TestCachingRealm()
        realm.name = realmName

        Object principal = realm.getAvailablePrincipal(principals)

        assertEquals username, principal

        verify principals
    }

    @Test
    void testGetAvailablePrincipalWithoutRealmPrincipals() {

        def realmName = "testRealm"
        def username = "foo"

        def principals = createStrictMock(PrincipalCollection)

        expect(principals.isEmpty()).andReturn false
        expect(principals.fromRealm(eq(realmName))).andReturn null
        expect(principals.getPrimaryPrincipal()).andReturn username

        replay principals

        CachingRealm realm = new TestCachingRealm()
        realm.name = realmName

        Object principal = realm.getAvailablePrincipal(principals)

        assertEquals username, principal

        verify principals
    }

    private static final class TestCachingRealm extends CachingRealm {

        def info;

        boolean templateMethodCalled = false
        boolean doClearCacheCalled = false

        boolean supports(AuthenticationToken token) {
            return true
        }

        AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
            return info;
        }

        @Override
        protected void afterCacheManagerSet() {
            super.afterCacheManagerSet()
            templateMethodCalled = true
        }

        @Override
        protected void doClearCache(PrincipalCollection principals) {
            super.doClearCache(principals)
            doClearCacheCalled = true
        }
    }
}
