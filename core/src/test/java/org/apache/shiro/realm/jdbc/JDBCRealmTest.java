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
package org.apache.shiro.realm.jdbc;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.codec.CodecSupport;
import org.apache.shiro.config.Ini;
import org.apache.shiro.ini.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.JdbcUtils;
import org.apache.shiro.util.ThreadContext;
import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.*;
import org.junit.rules.TestName;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;


/**
 * Test case for JDBCRealm.
 */
public class JDBCRealmTest {

    protected DefaultSecurityManager securityManager = null;
    protected AuthorizingRealm realm;
    protected final String username = "testUser";
    protected final String plainTextPassword = "testPassword";
    protected final String salt = username;  //Default impl of getSaltForUser returns username
    protected final String testRole = "testRole";
    protected final String testPermissionString = "testDomain:testTarget:testAction";
    
    // Maps keyed on test method name so setup/teardown can manage per test resources
    protected HashMap<String, JdbcRealm> realmMap = new HashMap<String, JdbcRealm>();
    protected HashMap<String, DataSource> dsMap = new HashMap<String, DataSource>();

    @Rule 
    public TestName name = new TestName();

    @Before
    public void setup() {
        ThreadContext.remove();
        Ini config = new Ini();
        config.setSectionProperty("main", "myRealm", "org.apache.shiro.realm.jdbc.JdbcRealm");
        config.setSectionProperty("main", "myRealmCredentialsMatcher", "org.apache.shiro.authc.credential.Sha256CredentialsMatcher");
        config.setSectionProperty("main", "myRealm.credentialsMatcher", "$myRealmCredentialsMatcher");
        config.setSectionProperty("main", "securityManager.sessionManager.sessionValidationSchedulerEnabled", "false");
        
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(config);
        securityManager = (DefaultSecurityManager) factory.createInstance();
        SecurityUtils.setSecurityManager(securityManager);
        
        // Create a database and realm for the test
        createRealm(name.getMethodName()); 
    }

    @After
    public void tearDown() {
        final String testName = name.getMethodName();
        shutDown(testName);
        SecurityUtils.setSecurityManager(null);
        securityManager.destroy();
        ThreadContext.remove();
    }
    
    @Test
    public void testUnSaltedSuccess() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        currentUser.logout();
    }
    
    @Test
    public void testUnSaltedWrongPassword() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, "passwrd");
        try {
            currentUser.login(token);
        } catch (IncorrectCredentialsException ex) {
            // Expected
        }
    }
    
    @Test
    public void testUnSaltedMultipleRows() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        Connection conn = dsMap.get(testMethodName).getConnection();
        Statement sql = conn.createStatement();
        sql.executeUpdate("insert into users values ('" + username + "', 'dupe')");
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, "passwrd");
        try {
            currentUser.login(token);
        } catch (AuthenticationException ex) {
            // Expected
        }
    }
    
    @Test
    public void testSaltColumnSuccess() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createSaltColumnSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.COLUMN);
        realm.setSaltIsBase64Encoded(false);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        currentUser.logout();
    }
    
    @Test
    public void testBase64EncodedSaltColumnSuccess() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createSaltColumnSchema(testMethodName, true);
        realm.setSaltStyle(JdbcRealm.SaltStyle.COLUMN);

        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        currentUser.logout();
    }

    @Test
    public void testSaltColumnWrongPassword() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createSaltColumnSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.COLUMN);
        realm.setSaltIsBase64Encoded(false);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, "passwrd");
        try {
            currentUser.login(token);
        } catch (IncorrectCredentialsException ex) {
            // Expected
        }
    }

    @Test
    public void testBase64SaltColumnWrongPassword() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createSaltColumnSchema(testMethodName, true);
        realm.setSaltStyle(JdbcRealm.SaltStyle.COLUMN);
        realm.setSaltIsBase64Encoded(false);

        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, "passwrd");
        try {
            currentUser.login(token);
        } catch (IncorrectCredentialsException ex) {
            // Expected
        }
    }
    
    @Test
    public void testExternalSuccess() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, true);
        realm.setSaltStyle(JdbcRealm.SaltStyle.EXTERNAL);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        currentUser.logout();
    }
    
    @Test
    public void testExternalWrongPassword() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, true);
        realm.setSaltStyle(JdbcRealm.SaltStyle.EXTERNAL);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, "passwrd");
        try {
            currentUser.login(token);
        } catch (IncorrectCredentialsException ex) {
            // Expected
        }
    }
    
    @Test
    public void testRolePresent() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        Assert.assertTrue(currentUser.hasRole(testRole));
    }
    
    @Test
    public void testRoleNotPresent() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        Assert.assertFalse(currentUser.hasRole("Game Overall Director"));
    }
    
    @Test
    public void testPermissionPresent() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        realm.setPermissionsLookupEnabled(true);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        Assert.assertTrue(currentUser.isPermitted(testPermissionString));
    }
    
    @Test
    public void testPermissionNotPresent() throws Exception {
        String testMethodName = name.getMethodName();
        JdbcRealm realm = realmMap.get(testMethodName);
        createDefaultSchema(testMethodName, false);
        realm.setSaltStyle(JdbcRealm.SaltStyle.NO_SALT);
        realm.setPermissionsLookupEnabled(true);
        
        Subject.Builder builder = new Subject.Builder(securityManager);
        Subject currentUser = builder.buildSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, plainTextPassword);
        currentUser.login(token);
        Assert.assertFalse(currentUser.isPermitted("testDomain:testTarget:specialAction"));
    }
    
    /**
     * Creates a realm for a test method and puts it in the realMap.
     */
    protected void createRealm(String testMethodName) {
        JdbcRealm realm = (JdbcRealm) securityManager.getRealms().iterator().next();
        realmMap.put(testMethodName, realm);
    }
    
    /**
     * Shuts down the database and removes the realm from the realm map.
     */
    protected void shutDown(String testName) {
        Connection conn = null;
        Statement sql = null;
        DataSource ds = dsMap.get(testName);
        try {
            Connection c = ds.getConnection();
            Statement s = c.createStatement();
            s.executeUpdate("SHUTDOWN");
        } catch (SQLException ex) {
            // ignore
        } finally {
            JdbcUtils.closeStatement(sql);
            JdbcUtils.closeConnection(conn);
            dsMap.remove(testName);
            realmMap.remove(testName);
        }
    }
    
    /**
     * Creates a test database with the default (no separate salt column) schema, salting with
     * username if salted is true. Sets the DataSource of the realm associated with the test
     * to a DataSource connected to the database.  (To prevent concurrency problems when tests
     * are executed in multithreaded mode, each test method gets its own database.)
     */
    protected void createDefaultSchema(String testName, boolean salted) {
        JDBCDataSource ds = new JDBCDataSource();
        ds.setDatabase("jdbc:hsqldb:mem:" + name);
        ds.setUser("SA");
        ds.setPassword("");
        Connection conn = null;
        Statement sql = null;
        try {
            conn = ds.getConnection();
            sql = conn.createStatement();
            sql.executeUpdate("create table users (username varchar(20), password varchar(100))");
            Sha256Hash sha256Hash = salted ? new Sha256Hash(plainTextPassword, salt) :
                new Sha256Hash(plainTextPassword);
            String password = sha256Hash.toHex();
            sql.executeUpdate("insert into users values ('" + username + "', '" + password + "')");
        } catch (SQLException ex) {
            Assert.fail("Exception creating test database");
        } finally {
            JdbcUtils.closeStatement(sql);
            JdbcUtils.closeConnection(conn);
        }
        createRolesAndPermissions(ds);
        realmMap.get(testName).setDataSource(ds);
        dsMap.put(testName, ds);
    }
    
    /**
     * Creates a test database with a separate salt column in the users table. Sets the
     * DataSource of the realm associated with the test to a DataSource connected to the database.
     * @param The name of the test which is used as the key when saving the created realm in the realmMap
     * @param base64EncodeSalt if true, the salt will be base64 encoded before it's stored in the database
     */
    protected void createSaltColumnSchema(String testName, boolean base64EncodeSalt) {
        JDBCDataSource ds = new JDBCDataSource();
        ds.setDatabase("jdbc:hsqldb:mem:" + name);
        ds.setUser("SA");
        ds.setPassword("");
        Connection conn = null;
        Statement sql = null;
        try {
            conn = ds.getConnection();
            sql = conn.createStatement();
            sql.executeUpdate(
                    "create table users (username varchar(20), password varchar(100), password_salt varchar(20))");
            Sha256Hash sha256Hash = new Sha256Hash(plainTextPassword, salt);
            String password = sha256Hash.toHex();
            String maybeBase64EncodedSalt = base64EncodeSalt ? Base64.encodeToString(CodecSupport.toBytes(salt)) : salt;
            sql.executeUpdate("insert into users values ('" + username + "', '" + password + "', '" + maybeBase64EncodedSalt + "')");
        } catch (SQLException ex) {
            Assert.fail("Exception creating test database");
        } finally {
            JdbcUtils.closeStatement(sql);
            JdbcUtils.closeConnection(conn);
        }
        createRolesAndPermissions(ds);
        realmMap.get(testName).setDataSource(ds);
        dsMap.put(testName, ds);
    }
    
    /**
     * Creates and adds test data to user_role and roles_permissions tables.
     */
    protected void createRolesAndPermissions(DataSource ds) {
        Connection conn = null;;
        Statement sql = null;
        try {
            conn = ds.getConnection();
            sql = conn.createStatement();
            sql.executeUpdate("create table user_roles (username varchar(20), role_name varchar(20))");
            sql.executeUpdate("insert into user_roles values ('" + username + "', '" + testRole + "')");
            sql.executeUpdate("create table roles_permissions (role_name varchar(20), permission varchar(40))");
            sql.executeUpdate(
                    "insert into roles_permissions values ('" + testRole + "', '" + testPermissionString + "')");
        } catch (SQLException ex) {
            Assert.fail("Exception adding test role and permission");
        } finally {
            JdbcUtils.closeStatement(sql);
            JdbcUtils.closeConnection(conn);
        }
    }
}
