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
package org.apache.shiro.config;

import static junit.framework.Assert.*;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.junit.Test;

import java.util.Collection;

/**
 * Unit tests for the {@link IniSecurityManagerFactory} implementation.
 *
 * @author The Apache Shiro Project (shiro-dev@incubator.apache.org)
 * @since 1.0
 */
public class IniSecurityManagerFactoryTest {

    IniSecurityManagerFactory factory;

    @Test
    public void testGetInstanceWithoutIni() {
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory();
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    public void testGetInstanceWithResourcePath() {
        String path = "classpath:org/apache/shiro/config/IniSecurityManagerFactoryTest.ini";
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(path);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    public void testGetInstanceWithEmptyIni() {
        Ini ini = new Ini();
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
    }

    @Test
    public void testGetInstanceWithSimpleIni() {
        Ini ini = new Ini();
        ini.setSectionProperty(IniSecurityManagerFactory.MAIN_SECTION_NAME, "securityManager.globalSessionTimeout", "5000");
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();
        assertNotNull(sm);
        assertTrue(sm instanceof DefaultSecurityManager);
        assertEquals(5000, ((DefaultSecurityManager) sm).getGlobalSessionTimeout());
    }

    @Test
    public void testGetInstanceWithConfiguredRealm() {
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        section.put("propsRealm", PropertiesRealm.class.getName());

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
    public void testGetInstanceWithAutomaticallyCreatedIniRealm() {
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


}
