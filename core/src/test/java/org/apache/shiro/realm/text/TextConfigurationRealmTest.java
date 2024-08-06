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

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.ImmutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("checkstyle:MagicNumber")
public class TextConfigurationRealmTest {

    private TestRealm realm;

    private void setRoles() {
        StringBuilder roleDefinitions = new StringBuilder()
                .append("role1 = role1_permission1\n")
                .append("role2 = role2_permission1, role2_permission2\n");
        realm.setRoleDefinitions(roleDefinitions.toString());
    }

    private void setUsers() {
        StringBuilder userDefinitions = new StringBuilder();
        for (int i = 1; i < 3; i++) {
            userDefinitions.append(String.format("user%1$d = user%1$d_password, role1, role2%n", i));
        }
        realm.setUserDefinitions(userDefinitions.toString());
    }

    private void setUpForReadConfigurationTest() {
        realm = new TestRealm() {
            /*
             * Demonstrates that a lock can't be obtained on the realm by a read thread until after
             * the lock is released.
             */
            public void test(Thread runnable) throws InterruptedException {
                // Obtain the realm's locks
                usersLock.writeLock().lock();
                try {
                    rolesLock.writeLock().lock();
                    try {
                        // Any read threads attempting to obtain the realms lock will block
                        runnable.start();
                        Thread.sleep(500);
                        // Process role and user definitions
                        realm.onInit();

                    } finally {
                        rolesLock.writeLock().unlock();
                    }
                } finally {
                    usersLock.writeLock().unlock();
                }
            }
        };
        setRoles();
        setUsers();
    }

    /*
     * Executes a test that attempts to read to read from a realm before it is loaded.
     */
    private void executeTest(Runnable runnable) throws InterruptedException {
        TestThread testThread = new TestThread(runnable);
        Thread testTask = new Thread(testThread);
        realm.test(testTask);
        testTask.join(500);
        // Check whether any assertion error was thrown by the read thread
        testThread.test();
    }

    /*
     * Tests that roles and account can't be tested while the realm is being loaded.
     */
    @Test
    void testRoleAndUserAccount() throws InterruptedException {
        setUpForReadConfigurationTest();
        executeTest(new Runnable() {
            public void run() {
                assertTrue(realm.roleExists("role1"), "role not found when it was expected");
                assertTrue(realm.accountExists("user1"), "user not found when it was expected");
            }
        });
    }

    /*
     * Tests that roles can't be read while the realm is being loaded.
     */
    @Test
    void testHasRole() throws InterruptedException {
        setUpForReadConfigurationTest();
        executeTest(new Runnable() {
            public void run() {
                PrincipalCollection principalCollection = ImmutablePrincipalCollection.ofSinglePrincipal("user1", "realm1");
                assertTrue(realm.hasRole(principalCollection, "role2"),
                        "principal doesn't have role when it should");
                assertTrue(realm.hasAllRoles(principalCollection, Arrays.asList(new String[] {"role1", "role2"})),
                        "principal doesn't have all roles when it should");
            }
        });
    }

    /*
     * Tests that roles can't be checked while the realm is being loaded.
     */
    @Test
    void testCheckRole() throws InterruptedException {
        setUpForReadConfigurationTest();
        executeTest(new Runnable() {
            public void run() {
                PrincipalCollection principalCollection = ImmutablePrincipalCollection.ofSinglePrincipal("user1", "realm1");
                try {
                    realm.checkRoles(principalCollection, new String[] {"role1", "role2"});
                } catch (AuthorizationException ae) {
                    fail("principal doesn't have all roles when it should");
                }
            }
        });
    }

    /*
     * Tests that a principal's permissions can't be checked while the realm is being loaded.
     */
    @Test
    void testCheckPermission() throws InterruptedException {
        setUpForReadConfigurationTest();
        executeTest(new Runnable() {
            public void run() {
                PrincipalCollection principalCollection = ImmutablePrincipalCollection.ofSinglePrincipal("user1", "realm1");
                try {
                    realm.checkPermission(principalCollection, "role1_permission1");
                    realm.checkPermissions(principalCollection, new String[] {"role1_permission1", "role2_permission2"});
                } catch (AuthorizationException ae) {
                    fail("principal doesn't have permission when it should");
                }
            }
        });
    }

    /*
     * Tests that a principal's permissions can't be checked while the realm is being loaded.
     */
    @Test
    void testIsPermitted() throws InterruptedException {
        setUpForReadConfigurationTest();
        executeTest(new Runnable() {

            public void run() {
                PrincipalCollection principalCollection = ImmutablePrincipalCollection.ofSinglePrincipal("user1", "realm1");
                assertTrue(realm.isPermitted(principalCollection,
                        "role1_permission1"),
                        "permission not permitted when it should be");
                assertTrue(realm.isPermittedAll(principalCollection,
                                "role1_permission1", "role2_permission2"),
                                "permission not permitted when it should be");
            }
        });
    }

    /*
     * Test that role definitions cannot be updated when a read thread holds the realm's lock.
     */
    @Test
    void testProcessRoleDefinitions() throws InterruptedException {
        realm = new TestRealm() {
            public void test(Thread runnable) throws InterruptedException {
                // While the realm's lock is held by this thread role definitions cannot be processed
                // Obtain the realm's locks
                rolesLock.writeLock().lock();
                try {
                    runnable.start();
                    Thread.sleep(500);
                    // No role until lock is released and role definitions are processed
                    assertThat(realm.roleExists("role1")).as("role exists when it shouldn't").isFalse();
                } finally {
                    rolesLock.writeLock().unlock();
                }
            }
        };
        // A thread to process new role definitions
        TestThread testThread = new TestThread(new Runnable() {
            public void run() {
                try {
                    realm.processRoleDefinitions();
                } catch (ParseException e) {
                    fail("Unable to parse role definitions");
                }
            }
        });
        setRoles();
        Thread testTask = new Thread(testThread);
        realm.test(testTask);
        testTask.join(500);
        assertThat(realm.roleExists("role1")).as("role doesn't exist when it should").isTrue();
        testThread.test();
    }

    /*
     * Test that user definitions cannot be updated when a read thread holds the realm's lock.
     */
    @Test
    void testProcessUserDefinitions() throws InterruptedException {
        realm = new TestRealm() {
            public void test(Thread runnable) throws InterruptedException {
                // While the realm's lock is held by this thread user definitions cannot be processed
                // Obtain the realm's locks
                usersLock.writeLock().lock();
                try {
                    runnable.start();
                    Thread.sleep(500);
                    // No account until lock is released and user definitions are processed
                    assertThat(realm.accountExists("user1")).as("account exists when it shouldn't").isFalse();
                } finally {
                    usersLock.writeLock().unlock();
                }
            }
        };
        TestThread testThread = new TestThread(new Runnable() {
            public void run() {
                try {
                    realm.processUserDefinitions();
                } catch (ParseException e) {
                    fail("Unable to parse user definitions");
                }
            }
        });
        setUsers();
        Thread testTask = new Thread(testThread);
        realm.test(testTask);
        testTask.join(500);
        assertThat(realm.accountExists("user1")).as("account doesn't exist when it should").isTrue();
        testThread.test();
    }

    /*
     * A Class that captures a thread's assertion error.
     */
    private class TestThread implements Runnable {
        private Runnable test;
        private volatile AssertionError ae;

        TestThread(Runnable test) {
            this.test = test;
        }

        public void run() {
            try {
                test.run();
            } catch (AssertionError ae) {
                this.ae = ae;
            }
        }

        public void test() {
            if (ae != null) {
                throw ae;
            }
        }
    }

    /*
     * Provides an additional method that has access to the realm's lock for mutual exclusion.
     */
    private abstract static class TestRealm extends TextConfigurationRealm {

        public abstract void test(Thread runnable) throws InterruptedException;
    }
}
