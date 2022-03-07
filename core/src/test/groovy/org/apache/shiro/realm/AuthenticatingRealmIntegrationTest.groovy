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

import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.UsernamePasswordToken
import org.apache.shiro.config.Ini
import org.apache.shiro.ini.IniSecurityManagerFactory
import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.subject.Subject
import org.junit.Test

import static org.junit.Assert.*

/**
 * Integration tests for the AuthenticatingRealm implementation.
 *
 * @since 1.2.1
 */
class AuthenticatingRealmIntegrationTest {

    @Test
    void testShiro354() {

        Ini ini = new Ini();
        ini.load('''

        [main]
        realm = org.apache.shiro.realm.TestAuthenticatingRealm
        securityManager.realms = $realm
        cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
        securityManager.cacheManager = $cacheManager
        # if you comment this line out, the test will fail as expected:
        realm.authenticationCachingEnabled = true

        ''');

        SecurityManager sm = new IniSecurityManagerFactory(ini).getInstance();

        AuthenticationToken token = new UsernamePasswordToken("user1", "secret");

        Subject subject = new Subject.Builder(sm).buildSubject();
        subject.login(token);

        Subject subject2 = new Subject.Builder(sm).buildSubject();
        subject2.login(token);

        //2 login calls for the same account, but the count on realm.doGetAuthenticationInfo should only be 1 due to caching:
        assertEquals 1, sm.getRealms().iterator().next().authenticationInfoCount
    }
}
