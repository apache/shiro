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
package org.apache.shiro.config

import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.cache.Cache
import org.apache.shiro.cache.MapCache
import org.apache.shiro.crypto.hash.Sha256Hash
import org.apache.shiro.ini.IniSecurityManagerFactory
import org.apache.shiro.mgt.DefaultSecurityManager
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.realm.Realm
import org.apache.shiro.realm.text.IniRealm
import org.apache.shiro.realm.text.PropertiesRealm
import org.apache.shiro.session.Session
import org.apache.shiro.session.mgt.AbstractSessionManager
import org.apache.shiro.session.mgt.DefaultSessionManager
import org.apache.shiro.session.mgt.eis.CachingSessionDAO
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO
import org.apache.shiro.session.mgt.eis.SessionDAO
import org.apache.shiro.subject.Subject
import org.junit.Test

import static org.junit.Assert.*

/**
 * Unit tests for the {@link IniSecurityManagerFactory} implementation.
 *
 * @since 1.0
 */
class IniSecurityManagerFactoryTest {

    @Test
    void testGetInstanceWithoutIni() {
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory();
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    void testGetInstanceWithResourcePath() {
        String path = "classpath:org/apache/shiro/config/IniSecurityManagerFactoryTest.ini";
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(path);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    void testGetInstanceWithEmptyIni() {
        Ini ini = new Ini();
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    void testGetInstanceWithSimpleIni() {
        Ini ini = new Ini();
        ini.setSectionProperty(IniSecurityManagerFactory.MAIN_SECTION_NAME,
                "securityManager.sessionManager.globalSessionTimeout", "5000");
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
        assertEquals(5000, ((AbstractSessionManager) ((DefaultSecurityManager) sm).getSessionManager()).getGlobalSessionTimeout());
    }

    @Test
    void testGetInstanceWithConfiguredRealm() {
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        section.put("propsRealm", PropertiesRealm.class.getName());
        section.put("propsRealm.resourcePath",
                "classpath:org/apache/shiro/config/IniSecurityManagerFactoryTest.propsRealm.properties");

        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
        Collection<Realm> realms = ((DefaultSecurityManager) sm).getRealms();
        assertEquals(1, realms.size());
        Realm realm = realms.iterator().next();
        assertTrue(realm instanceof PropertiesRealm);
    }

    @Test
    void testGetInstanceWithAutomaticallyCreatedIniRealm() {
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniRealm.USERS_SECTION_NAME);
        section.put("admin", "admin");

        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
        Collection<Realm> realms = ((DefaultSecurityManager) sm).getRealms();
        assertEquals(1, realms.size());
        Realm realm = realms.iterator().next();
        assertTrue(realm instanceof IniRealm);
        assertTrue(((IniRealm) realm).accountExists("admin"));
    }

    /**
     * Test for issue <a href="https://issues.apache.org/jira/browse/SHIRO-125">SHIRO-125</a>.
     */
    @Test
    void testImplicitIniRealmWithAdditionalRealmConfiguration() {

        Ini ini = new Ini();

        //The users section below should create an implicit 'iniRealm' instance in the
        //main configuration.  So we should be able to set properties on it immediately
        //such as the Sha256 credentials matcher:
        Ini.Section main = ini.addSection("main");
        main.put("credentialsMatcher", "org.apache.shiro.authc.credential.Sha256CredentialsMatcher");
        main.put("iniRealm.credentialsMatcher", '$credentialsMatcher');

        //create a users section - user 'admin', with a Sha256-hashed 'admin' password (hex encoded):
        Ini.Section users = ini.addSection(IniRealm.USERS_SECTION_NAME);
        users.put("admin", new Sha256Hash("secret").toString());

        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();

        //go ahead and try to log in with the admin user, ensuring the
        //iniRealm has a Sha256CredentialsMatcher enabled:

        //try to log-in:
        Subject subject = new Subject.Builder(sm).buildSubject();
        //ensure thread clean-up after the login method returns.  Test cases only:
        subject.execute(new Runnable() {
            public void run() {
                //the plain-text 'secret' should be converted to an Sha256 hash first
                //by the CredentialsMatcher.  This should return quietly if
                //this test case is valid:
                SecurityUtils.getSubject().login(new UsernamePasswordToken("admin", "secret"));
            }
        });
        assertTrue(subject.getPrincipal().equals("admin"));
    }

    /**
     * Test for issue <a href="https://issues.apache.org/jira/browse/SHIRO-322">SHIRO-322</a>.
     */
    @Test
    void testImplicitIniRealmWithConfiguredPermissionResolver() {
        def ini = new Ini();
        ini.load('''
            [main]
            # The MockPermissionResolver is a peer class to this test class.
            permissionResolver = org.apache.shiro.config.MockPermissionResolver
            iniRealm.permissionResolver = $permissionResolver

            [users]
            jsmith = secret, author

            [roles]
            author = book:write
        ''');

        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.instance

        def realm = sm.realms[0]
        assertNotNull realm
        def permResolver = realm.permissionResolver
        assertTrue permResolver instanceof MockPermissionResolver
        assertTrue permResolver.invoked
    }

    /**
     * Test case for issue <a href="https://issues.apache.org/jira/browse/SHIRO-95">SHIRO-95</a>.
     */
    @Test
    void testCacheManagerConfigOrderOfOperations() {

        Ini ini = new Ini();
        Ini.Section main = ini.addSection(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        //create a non-default CacheManager:
        main.put("cacheManager", "org.apache.shiro.config.HashMapCacheManager");

        //now add a session DAO after the cache manager has been set - this is what tests the user-reported issue
        main.put("sessionDAO", "org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO");
        main.put("securityManager.sessionManager.sessionDAO", '$sessionDAO');

        //add the cache manager after the sessionDAO has been set:
        main.put("securityManager.cacheManager", '$cacheManager');

        //add a test user:
        ini.setSectionProperty(IniRealm.USERS_SECTION_NAME, "admin", "admin");

        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();

        //try to log-in:
        Subject subject = new Subject.Builder(sm).buildSubject();
        subject.login(new UsernamePasswordToken("admin", "admin"));
        Session session = subject.getSession();
        session.setAttribute("hello", "world");
        //session should have been started, and a cache is in use.  Assert that the SessionDAO is still using
        //the cache instances provided by our custom CacheManager and not the Default MemoryConstrainedCacheManager

        SessionDAO sessionDAO = ((DefaultSessionManager) ((DefaultSecurityManager) sm).getSessionManager()).getSessionDAO();
        assertTrue(sessionDAO instanceof EnterpriseCacheSessionDAO);
        CachingSessionDAO cachingSessionDAO = (CachingSessionDAO) sessionDAO;
        Cache activeSessionsCache = cachingSessionDAO.getActiveSessionsCache();
        assertTrue(activeSessionsCache instanceof MapCache);
        MapCache mapCache = (MapCache) activeSessionsCache;

        //this is the line that verifies Caches created by our specific CacheManager are not overwritten by the
        //default cache manager's caches:
        assertTrue(mapCache instanceof HashMapCacheManager.HashMapCache);
    }

}
