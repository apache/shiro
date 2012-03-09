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
package org.apache.shiro.authz;

import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;


import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static junit.framework.Assert.*;
import static org.hamcrest.CoreMatchers.*;

public class ModularRealmAuthorizerTest
{
    @Rule
    public ExpectedException expected = ExpectedException.none();

    private static String INVALID_PRIV = "priv:invalid";
    private static String VALID_PRIV = "priv:valid";

    private static String INVALID_ROLE = "invalid-role";
    private static String VALID_ROLE = "valid-role";

    private ModularRealmAuthorizer modRealmAuthz;
    
    private Collection<Realm> realms = new ArrayList<Realm>();

    private List<Permission> permissions = new ArrayList<Permission>();

    private List<String> roles = new ArrayList<String>();

    private PrincipalCollection principalCollection = EasyMock.createNiceMock(PrincipalCollection.class);
    
    @Before
    public void setUp()
    {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo(Collections.singleton(VALID_ROLE));
        authorizationInfo.addStringPermission(VALID_PRIV);

        permissions.add(new WildcardPermission(INVALID_PRIV));
        permissions.add(new WildcardPermission(VALID_PRIV));

        roles.add(INVALID_ROLE);
        roles.add(VALID_ROLE);
        
        realms.add(new ExceptionThrowingAuthorizingRealm());
        realms.add(new MockAuthorizingRealm(authorizationInfo));

        modRealmAuthz = new ModularRealmAuthorizer();
        modRealmAuthz.setRealms( realms );
    }

    /**
     * Tests setting the RolePermissionResolver is propagated to realms.
     */
    @Test
    public void testSettingOfRolePermissionResolver()
    {
        // make sure initializing a realm has a null rolePermissionResolver (or the next test is not valid)
        assertNull( new MockAuthorizingRealm().getRolePermissionResolver() );
        
        // make sure they are still null
        for ( Realm realm : realms )
        {
            assertNull( ( (AuthorizingRealm) realm ).getRolePermissionResolver() );
        }
        
        // now set the RolePermissionResolver
        RolePermissionResolver rolePermissionResolver = new RolePermissionResolver()
        {   
            public Collection<Permission> resolvePermissionsInRole( String roleString )
            {
                return null;
            }
        };
        modRealmAuthz.setRolePermissionResolver( rolePermissionResolver );
     
        // make sure they are set
        for ( Realm realm : realms )
        {
            // check for same instance
            assertTrue( ( (AuthorizingRealm) realm ).getRolePermissionResolver() == rolePermissionResolver );
        }
        
        // add a new realm and make sure the RolePermissionResolver is set
        MockAuthorizingRealm mockRealm = new MockAuthorizingRealm();
        realms.add( mockRealm );
        modRealmAuthz.setRealms( realms );
        assertTrue( ((AuthorizingRealm) mockRealm).getRolePermissionResolver() == rolePermissionResolver );
        
        
        // TODO: no way to unset them, not sure if that is a valid use case, but this is conistent with the PermissionResolver logic
//        // now just to be sure, unset them
//        modRealmAuthz.setRolePermissionResolver( null );
//        for ( Realm realm : realms )
//        {
//            Assert.assertNull( ((AuthorizingRealm)realm).getRolePermissionResolver() );
//        }
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedWithString() {

        try {
            modRealmAuthz.isPermitted(principalCollection, VALID_PRIV);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertFalse( modRealmAuthz.isPermitted( principalCollection, INVALID_PRIV ) );
        assertTrue(modRealmAuthz.isPermitted(principalCollection, VALID_PRIV));
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedWithPermission() {

        try {
            modRealmAuthz.isPermitted(principalCollection, new WildcardPermission(VALID_PRIV));
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertFalse(modRealmAuthz.isPermitted(principalCollection, new WildcardPermission(INVALID_PRIV)));
        assertTrue(modRealmAuthz.isPermitted(principalCollection, new WildcardPermission(VALID_PRIV)));
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedWithStrings() {

        try {
            modRealmAuthz.isPermitted(principalCollection, INVALID_PRIV, VALID_PRIV);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertThat( modRealmAuthz.isPermitted( principalCollection, INVALID_PRIV, VALID_PRIV ),
                    equalTo( new boolean[]{ false, true } ) );
        assertThat( modRealmAuthz.isPermitted( principalCollection, permissions ),
                    equalTo( new boolean[]{ false, true } ) );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedWithPermissions() {

        try {
            modRealmAuthz.isPermitted(principalCollection, permissions);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertThat(modRealmAuthz.isPermitted(principalCollection, permissions), equalTo(new boolean[]{ false, true }));
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedAllWithStrings() {

        try {
            modRealmAuthz.isPermittedAll( principalCollection, INVALID_PRIV, VALID_PRIV );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertFalse( modRealmAuthz.isPermittedAll( principalCollection, INVALID_PRIV, VALID_PRIV ) );
        assertTrue( modRealmAuthz.isPermittedAll( principalCollection, VALID_PRIV, VALID_PRIV ) );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testIsPermittedAllWithPermissions() {

        try {
            modRealmAuthz.isPermittedAll(principalCollection, permissions);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertFalse( modRealmAuthz.isPermittedAll( principalCollection, permissions ) );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testHasRole() {

        try {
            modRealmAuthz.hasRole( principalCollection, VALID_ROLE );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertTrue(modRealmAuthz.hasRole( principalCollection, VALID_ROLE));
        assertFalse(modRealmAuthz.hasRole( principalCollection, INVALID_ROLE ));
    }

    /**
     * @since 1.3
     */
    @Test
    public void testHasRoles() {

        try {
            modRealmAuthz.hasRoles( principalCollection, roles );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertThat( modRealmAuthz.hasRoles( principalCollection, roles ), equalTo( new boolean[]{ false, true } ) );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testHasAllRoles() {

        try {
            modRealmAuthz.hasAllRoles( principalCollection, roles );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        assertFalse( modRealmAuthz.hasAllRoles( principalCollection, roles ) );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckPermissionWithString() {

        try {
            modRealmAuthz.checkPermission( principalCollection, VALID_PRIV );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkPermission( principalCollection, VALID_PRIV );
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckPermissionWithStrings() {

        try {
            modRealmAuthz.checkPermission(principalCollection, new WildcardPermission(VALID_PRIV));
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkPermission(principalCollection, new WildcardPermission(VALID_PRIV));
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckPermissionsWithStrings() {

        try {
            modRealmAuthz.checkPermissions(principalCollection, VALID_PRIV );
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkPermissions(principalCollection, VALID_PRIV);
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckPermissionsWithPermissions() {

        Collection<Permission> validPermissions = Collections.<Permission>singleton(new WildcardPermission(VALID_PRIV));
        try {
            modRealmAuthz.checkPermissions(principalCollection, validPermissions);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkPermissions(principalCollection, validPermissions);
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckRole() {

        try {
            modRealmAuthz.checkRole(principalCollection, VALID_ROLE);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkRole(principalCollection, VALID_ROLE);
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckRoles() {

        try {
            modRealmAuthz.checkRoles(principalCollection, VALID_ROLE);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkRoles(principalCollection, VALID_ROLE);
    }

    /**
     * @since 1.3
     */
    @Test
    public void testCheckRolesCollection() {

        Collection<String> validRoles = Collections.singleton(VALID_ROLE);
        try {
            modRealmAuthz.checkRoles(principalCollection, validRoles);
            fail("Expected AuthorizationException");
        }
        catch(AuthorizationException e){
            // expected
        }

        // now with ignoring exceptions
        modRealmAuthz.setIgnoreExceptionsFromRealms( true );

        modRealmAuthz.checkRoles(principalCollection, validRoles);
    }

    class MockAuthorizingRealm extends AuthorizingRealm {

        private final AuthorizationInfo authorizationInfo;

        public MockAuthorizingRealm () {
            this(null);
        }

        public MockAuthorizingRealm( AuthorizationInfo authorizationInfo ) {
            this.authorizationInfo = authorizationInfo;
        }

        @Override
        protected AuthorizationInfo doGetAuthorizationInfo( PrincipalCollection principals ) {
            return authorizationInfo;
        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) {
            return null;
        }
    }

    class ExceptionThrowingAuthorizingRealm extends AuthorizingRealm {

        @Override
        protected AuthorizationInfo doGetAuthorizationInfo( PrincipalCollection principals ) {
            throw new AuthorizationException( "Thrown by a Test Realm that only throws exceptions." );
        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) {
            return null;
        }
    }
}
