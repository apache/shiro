/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.crowd;

import java.util.Arrays;
import java.util.EnumSet;

import com.atlassian.crowd.integration.service.soap.client.SecurityServerClient;
import org.junit.Test;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;


/**
 * @version $Revision: $ $Date: $
 */
public class CrowdRealmTest {

    @Test
    public void testAuthentication() throws Exception {

        SecurityServerClient client = createStrictMock(SecurityServerClient.class);
        expect(client.authenticatePrincipalSimple("yoko", "barbie")).andReturn("UNUSED");
        replay(client);

        CrowdRealm realm = new CrowdRealm(client);
        realm.setName("NutHouse");

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));

        verify(client);
        assertNotNull(authenticationInfo);
        assertTrue(Arrays.equals("barbie".toCharArray(), (char[]) authenticationInfo.getCredentials()));

        PrincipalCollection collection = authenticationInfo.getPrincipals();
        assertNotNull(collection);
        assertTrue(!collection.isEmpty());
        assertEquals("yoko", collection.getPrimaryPrincipal());
        assertTrue(!collection.getRealmNames().isEmpty());
        assertTrue(collection.getRealmNames().contains("NutHouse"));
        assertTrue(!collection.fromRealm("NutHouse").isEmpty());
        assertTrue(collection.fromRealm("NutHouse").contains("yoko"));
    }

    @Test
    public void testDefaultRoles() throws Exception {

        SecurityServerClient client = createStrictMock(SecurityServerClient.class);
        expect(client.authenticatePrincipalSimple("yoko", "barbie")).andReturn("UNUSED");
        expect(client.findRoleMemberships("yoko")).andReturn(new String[]{"big_sister", "table_setter", "dog_walker"});
        replay(client);

        CrowdRealm realm = new CrowdRealm(client);
        realm.setName("NutHouse");

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

        verify(client);
        assertTrue(!authorizationInfo.getRoles().isEmpty());
        assertTrue(authorizationInfo.getRoles().contains("big_sister"));
        assertTrue(authorizationInfo.getRoles().contains("table_setter"));
        assertTrue(authorizationInfo.getRoles().contains("dog_walker"));
    }

    @Test
    public void testRoleMemberships() throws Exception {

        SecurityServerClient client = createStrictMock(SecurityServerClient.class);
        expect(client.authenticatePrincipalSimple("yoko", "barbie")).andReturn("UNUSED");
        expect(client.findRoleMemberships("yoko")).andReturn(new String[]{"big_sister", "table_setter", "dog_walker"});
        replay(client);

        CrowdRealm realm = new CrowdRealm(client);
        realm.setName("NutHouse");
        realm.setRoleSources(EnumSet.of(RoleSource.ROLES_FROM_CROWD_ROLES));

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

        verify(client);
        assertTrue(!authorizationInfo.getRoles().isEmpty());
        assertTrue(authorizationInfo.getRoles().contains("big_sister"));
        assertTrue(authorizationInfo.getRoles().contains("table_setter"));
        assertTrue(authorizationInfo.getRoles().contains("dog_walker"));
    }


    @Test
    public void testGroupMemberships() throws Exception {

        SecurityServerClient client = createStrictMock(SecurityServerClient.class);
        expect(client.authenticatePrincipalSimple("yoko", "barbie")).andReturn("UNUSED");
        expect(client.findGroupMemberships("yoko")).andReturn(new String[]{"girls", "naughty"});
        replay(client);

        CrowdRealm realm = new CrowdRealm(client);
        realm.setName("NutHouse");
        realm.setRoleSources(EnumSet.of(RoleSource.ROLES_FROM_CROWD_GROUPS));

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

        verify(client);
        assertTrue(!authorizationInfo.getRoles().isEmpty());
        assertTrue(authorizationInfo.getRoles().contains("girls"));
        assertTrue(authorizationInfo.getRoles().contains("naughty"));
    }

    @Test
    public void testAll() throws Exception {

        SecurityServerClient client = createStrictMock(SecurityServerClient.class);
        expect(client.authenticatePrincipalSimple("yoko", "barbie")).andReturn("UNUSED");
        expect(client.findRoleMemberships("yoko")).andReturn(new String[]{"big_sister", "table_setter", "dog_walker"});
        expect(client.findGroupMemberships("yoko")).andReturn(new String[]{"girls", "naughty"});
        replay(client);

        CrowdRealm realm = new CrowdRealm(client);
        realm.setName("NutHouse");
        realm.setRoleSources(EnumSet.of(RoleSource.ROLES_FROM_CROWD_GROUPS, RoleSource.ROLES_FROM_CROWD_ROLES));

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

        verify(client);
        assertTrue(!authorizationInfo.getRoles().isEmpty());
        assertTrue(authorizationInfo.getRoles().contains("big_sister"));
        assertTrue(authorizationInfo.getRoles().contains("table_setter"));
        assertTrue(authorizationInfo.getRoles().contains("dog_walker"));
        assertTrue(authorizationInfo.getRoles().contains("girls"));
        assertTrue(authorizationInfo.getRoles().contains("naughty"));
    }

    public void testIntegration() throws Exception {

        CrowdRealm realm = new CrowdRealm();
        realm.setName("NutHouse");
        realm.setRoleSources(EnumSet.of(RoleSource.ROLES_FROM_CROWD_GROUPS, RoleSource.ROLES_FROM_CROWD_ROLES));

        AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new UsernamePasswordToken("yoko", "barbie"));

        assertNotNull(authenticationInfo);
        assertTrue(Arrays.equals("barbie".toCharArray(), (char[]) authenticationInfo.getCredentials()));

        PrincipalCollection collection = authenticationInfo.getPrincipals();
        assertNotNull(collection);
        assertTrue(!collection.isEmpty());
        assertEquals("yoko", collection.getPrimaryPrincipal());
        assertTrue(!collection.getRealmNames().isEmpty());
        assertTrue(collection.getRealmNames().contains("NutHouse"));
        assertTrue(!collection.fromRealm("NutHouse").isEmpty());
        assertTrue(collection.fromRealm("NutHouse").contains("yoko"));

        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(authenticationInfo.getPrincipals());

        assertTrue(!authorizationInfo.getRoles().isEmpty());
        assertTrue(authorizationInfo.getRoles().contains("big_sister"));
        assertTrue(authorizationInfo.getRoles().contains("table_setter"));
        assertTrue(authorizationInfo.getRoles().contains("dog_walker"));
        assertTrue(authorizationInfo.getRoles().contains("girls"));
        assertTrue(authorizationInfo.getRoles().contains("naughty"));
    }
}
