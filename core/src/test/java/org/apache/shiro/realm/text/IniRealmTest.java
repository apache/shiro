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
package org.apache.shiro.realm.text;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Unit tests for the {@link IniRealm} class.
 *
 * @since 1.0
 */
public class IniRealmTest {

    @Test
    public void testNullIni() {
        IniRealm realm = new IniRealm((Ini) null);
    }

    @Test
    public void testEmptyIni() {
        new IniRealm(new Ini());
    }

    @Test(expected = IllegalStateException.class)
    public void testInitWithoutIniResource() {
        new IniRealm().init();
    }

    @Test
    public void testIniFile() {
        IniRealm realm = new IniRealm();
        realm.setResourcePath("classpath:org/apache/shiro/realm/text/IniRealmTest.simple.ini");
        realm.init();
        assertTrue(realm.roleExists("admin"));
        UsernamePasswordToken token = new UsernamePasswordToken("user1", "user1");
        AuthenticationInfo info = realm.getAuthenticationInfo(token);
        assertNotNull(info);
        assertTrue(realm.hasRole(info.getPrincipals(), "admin"));
    }

    @Test
    public void testIniFileWithoutUsers() {
        IniRealm realm = new IniRealm();
        realm.setResourcePath("classpath:org/apache/shiro/realm/text/IniRealmTest.noUsers.ini");
        realm.init();
        assertTrue(realm.roleExists("admin"));
    }
}
