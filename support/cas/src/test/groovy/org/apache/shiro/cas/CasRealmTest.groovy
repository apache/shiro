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
package org.apache.shiro.cas

import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authz.AuthorizationInfo

import org.junit.Test

import static org.junit.Assert.*

/**
 * Unit tests for the {@link CasRealm} implementation.
 *
 * @since 1.2
 * @see <a href="https://github.com/bujiio/buji-pac4j">buji-pac4j</a>
 * @deprecated replaced with Shiro integration in <a href="https://github.com/bujiio/buji-pac4j">buji-pac4j</a>.
 */
@Deprecated
class CasRealmTest {

    /**
     * Creates a CAS realm with a ticket validator mock.
     *
     * @return CasRealm The CAS realm for testing.
     */
    private CasRealm createCasRealm() {
        new CasRealm(ticketValidator: new MockServiceTicketValidator());
    }

    @Test
    void testNoAttribute() {
        CasRealm casRealm = createCasRealm();
        CasToken casToken = new CasToken('$=defaultId');
        AuthenticationInfo authenticationInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authenticationInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.asList()[1] //returns a map
        assertEquals 0, attributes.size()
        AuthorizationInfo authorizationInfo = casRealm.doGetAuthorizationInfo(principals);
        assertNull authorizationInfo.stringPermissions
        assertNull authorizationInfo.roles
    }

    @Test
    void testNoAttributeDefaultRoleAndPermission() {
        CasRealm casRealm = createCasRealm();
        casRealm.defaultRoles = "defaultRole"
        casRealm.defaultPermissions = "defaultPermission"
        CasToken casToken = new CasToken('$=defaultId');
        AuthenticationInfo authenticationInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authenticationInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals 0, attributes.size()
        AuthorizationInfo authorizationInfo = casRealm.doGetAuthorizationInfo(principals);
        assertTrue authorizationInfo.roles.contains("defaultRole")
        assertTrue authorizationInfo.stringPermissions.contains("defaultPermission")
    }

    @Test
    void testNoAttributeDefaultRolesAndPermissions() {
        CasRealm casRealm = createCasRealm();
        casRealm.defaultRoles = "defaultRole1, defaultRole2"
        casRealm.defaultPermissions = "defaultPermission1,defaultPermission2"
        CasToken casToken = new CasToken('$=defaultId');
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals 0, attributes.size()
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals)
        assertEquals 2, authzInfo.roles.size()
        assertTrue authzInfo.roles.contains("defaultRole1")
        assertTrue authzInfo.roles.contains("defaultRole2")
        assertEquals 2, authzInfo.stringPermissions.size()
        assertTrue authzInfo.stringPermissions.contains("defaultPermission1")
        assertTrue authzInfo.stringPermissions.contains("defaultPermission2")
    }

    @Test
    void testRoleAndPermission() {
        CasRealm casRealm = createCasRealm();
        casRealm.roleAttributeNames = "role"
        casRealm.permissionAttributeNames = "permission"
        CasToken casToken = new CasToken('$=defaultId|role=aRole|permission=aPermission');
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals 2, attributes.size()
        assertEquals "aRole", attributes['role']
        assertEquals "aPermission", attributes['permission']
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals);
        assertTrue authzInfo.roles.contains("aRole")
        assertTrue authzInfo.stringPermissions.contains("aPermission")
    }

    @Test
    void testRolesAndPermissions() {
        CasRealm casRealm = createCasRealm();
        casRealm.setRoleAttributeNames("role1 , role2");
        casRealm.setPermissionAttributeNames("permission1,permission2");
        CasToken casToken = new CasToken(
                '$=defaultId|role1=role11 , role12|role2=role21,role22|permission1=permission11, permission12|permission2=permission21 ,permission22');
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals "role11 , role12", attributes['role1']
        assertEquals "role21,role22", attributes['role2']
        assertEquals "permission11, permission12", attributes['permission1']
        assertEquals "permission21 ,permission22", attributes['permission2']
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals);
        assertEquals 4, authzInfo.roles.size()
        assertTrue authzInfo.roles.contains("role11")
        assertTrue authzInfo.roles.contains("role12")
        assertTrue authzInfo.roles.contains("role21")
        assertTrue authzInfo.roles.contains("role22")
        assertTrue authzInfo.stringPermissions.contains("permission11")
        assertTrue authzInfo.stringPermissions.contains("permission12")
        assertTrue authzInfo.stringPermissions.contains("permission21")
        assertTrue authzInfo.stringPermissions.contains("permission22")
    }

    @Test
    void testNotRememberMe() {
        CasRealm casRealm = createCasRealm();
        CasToken casToken = new CasToken("\$=defaultId|$CasRealm.DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME=false");
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals "false", attributes[CasRealm.DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME]
        assertFalse casToken.rememberMe
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals);
        assertNull authzInfo.stringPermissions
        assertNull authzInfo.roles
    }

    @Test
    void testRememberMe() {
        CasRealm casRealm = createCasRealm();
        CasToken casToken = new CasToken("\$=defaultId|$CasRealm.DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME=true");
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals "true", attributes[CasRealm.DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME]
        assertTrue casToken.rememberMe
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals);
        assertNull authzInfo.stringPermissions
        assertNull authzInfo.roles
    }

    @Test
    void testRememberMeNewAttributeName() {
        CasRealm casRealm = createCasRealm();
        casRealm.rememberMeAttributeName = "rme"
        CasToken casToken = new CasToken('$=defaultId|rme=true');
        AuthenticationInfo authcInfo = casRealm.doGetAuthenticationInfo(casToken);
        def principals = authcInfo.principals
        assertEquals "defaultId", principals.primaryPrincipal
        def attributes = principals.oneByType(Map)
        assertEquals "true", attributes[casRealm.rememberMeAttributeName]
        assertTrue casToken.rememberMe
        AuthorizationInfo authzInfo = casRealm.doGetAuthorizationInfo(principals);
        assertNull authzInfo.stringPermissions
        assertNull authzInfo.roles
    }

}
