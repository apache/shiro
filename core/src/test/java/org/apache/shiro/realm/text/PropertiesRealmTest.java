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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.subject.ImmutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests that reloading a {@link PropertiesRealm} replaces its content: access can be revoked, not only granted.
 */
class PropertiesRealmTest {
    private static final String INITIAL = """
            user.alice = pass1, admin
            user.bob = pass2, admin
            role.admin = *
            """;

    @TempDir
    Path tempDir;

    private Path file;
    private PropertiesRealm realm;

    @BeforeEach
    void setUp() throws IOException {
        file = tempDir.resolve("users.properties");
        write(INITIAL);
        realm = new PropertiesRealm();
        realm.setResourcePath("file:" + file.toAbsolutePath());
        // reloads are triggered explicitly, no background thread
        realm.setReloadIntervalSeconds(0);
        realm.init();
    }

    @AfterEach
    void tearDown() {
        realm.destroy();
    }

    private void write(String content) throws IOException {
        Files.writeString(file, content);
    }

    private boolean authenticates(String user, String password) {
        return realm.getAuthenticationInfo(new UsernamePasswordToken(user, password)) != null;
    }

    private boolean permitted(String user, String permission) {
        PrincipalCollection principals = ImmutablePrincipalCollection.ofSinglePrincipal(user, realm.getName());
        return realm.isPermitted(principals, permission);
    }

    @Test
    void initialStateIsLoaded() {
        assertThat(authenticates("alice", "pass1")).isTrue();
        assertThat(authenticates("bob", "pass2")).isTrue();
        assertThat(permitted("bob", "anything:anything")).isTrue();
    }

    @Test
    void reloadRemovesDeletedUser() throws IOException {
        write("""
                user.bob = pass2, admin
                role.admin = *
                """);
        realm.restart();

        assertThat(authenticates("alice", "pass1")).isFalse();
        assertThat(permitted("alice", "anything:anything")).isFalse();
        assertThat(authenticates("bob", "pass2")).isTrue();
    }

    @Test
    void reloadRemovesNarrowedPermissions() throws IOException {
        write("""
                user.alice = pass1, admin
                user.bob = pass2, admin
                role.admin = app:read
                """);
        realm.restart();

        assertThat(permitted("bob", "app:read")).isTrue();
        assertThat(permitted("bob", "anything:anything")).isFalse();
    }

    @Test
    void reloadRemovesDroppedRole() throws IOException {
        write("""
                user.alice = pass1, admin, auditor
                user.bob = pass2, auditor
                role.admin = *
                role.auditor = audit:read
                """);
        realm.restart();
        assertThat(permitted("bob", "audit:read")).isTrue();
        assertThat(permitted("bob", "anything:anything")).isFalse();

        write("""
                user.alice = pass1, auditor
                user.bob = pass2
                role.auditor = audit:read
                """);
        realm.restart();
        assertThat(permitted("alice", "anything:anything")).isFalse();
        assertThat(permitted("alice", "audit:read")).isTrue();
        assertThat(permitted("bob", "audit:read")).isFalse();
    }

    @Test
    void reloadAddsAndUpdatesUsers() throws IOException {
        write("""
                user.alice = changed, admin
                user.carol = pass3, admin
                role.admin = *
                """);
        realm.restart();

        assertThat(authenticates("carol", "pass3")).isTrue();
        assertThat(authenticates("alice", "changed")).isTrue();
        assertThat(authenticates("bob", "pass2")).isFalse();
    }

    @Test
    void reloadClearsCachedInfo() throws IOException {
        realm.setCacheManager(new MemoryConstrainedCacheManager());
        realm.setAuthenticationCachingEnabled(true);
        realm.setAuthorizationCachingEnabled(true);
        assertThat(authenticates("alice", "pass1")).isTrue();
        assertThat(permitted("alice", "anything:anything")).isTrue();

        write("""
                user.bob = pass2, admin
                role.admin = *
                """);
        realm.restart();

        assertThat(authenticates("alice", "pass1")).isFalse();
        assertThat(permitted("alice", "anything:anything")).isFalse();
    }

    @Test
    void reloadRunsInitializationHooks() throws IOException {
        AtomicInteger initCalls = new AtomicInteger();
        PropertiesRealm hooked = new PropertiesRealm() {
            @Override
            public void onInit() {
                super.onInit();
                initCalls.incrementAndGet();
            }
        };
        hooked.setResourcePath("file:" + file.toAbsolutePath());
        hooked.setReloadIntervalSeconds(0);
        hooked.init();
        assertThat(initCalls).hasValue(1);

        hooked.restart();

        assertThat(initCalls).hasValue(2);
        hooked.destroy();
    }
}
