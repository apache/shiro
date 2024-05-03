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
package org.apache.shiro.session.mgt;

import org.apache.shiro.session.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("checkstyle:MagicNumber")
public class ExecutorServiceSessionValidationSchedulerTest {

    ExecutorServiceSessionValidationScheduler executorServiceSessionValidationScheduler;
    DefaultSessionManager defaultSessionManager;

    @BeforeEach
    public void setUp() {
        defaultSessionManager = new DefaultSessionManager();
        defaultSessionManager.setDeleteInvalidSessions(true);
        executorServiceSessionValidationScheduler = new ExecutorServiceSessionValidationScheduler();
        executorServiceSessionValidationScheduler.setSessionManager(defaultSessionManager);
        executorServiceSessionValidationScheduler.setThreadNamePrefix("test-");
        executorServiceSessionValidationScheduler.setSessionValidationInterval(1000L);
        executorServiceSessionValidationScheduler.enableSessionValidation();
    }

    @Test
    void timeoutSessionValidate() throws InterruptedException {
        Session session = new SimpleSession();
        session.setTimeout(2000L);
        defaultSessionManager.create(session);
        Thread.sleep(5000L);
        assertThat(defaultSessionManager.getActiveSessions()).isEmpty();
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isTrue();
    }

    @Test
    void stopSessionValidate() throws InterruptedException {
        Session session = new SimpleSession();
        session.setTimeout(10000L);
        defaultSessionManager.create(session);
        Thread.sleep(1000L);
        session.stop();
        Thread.sleep(3000L);
        assertThat(defaultSessionManager.getActiveSessions()).isEmpty();
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isTrue();
    }

    @Test
    void enableSessionValidation() throws InterruptedException {
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isTrue();
        executorServiceSessionValidationScheduler.disableSessionValidation();
        Thread.sleep(2000L);
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isFalse();
        executorServiceSessionValidationScheduler.enableSessionValidation();
        Thread.sleep(2000L);
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isTrue();
    }

    @Test
    void threadException() throws InterruptedException {
        Session session = new SimpleSession();
        defaultSessionManager = new FakeDefaultSessionManager();
        defaultSessionManager.setDeleteInvalidSessions(true);
        executorServiceSessionValidationScheduler = new ExecutorServiceSessionValidationScheduler();
        executorServiceSessionValidationScheduler.setSessionManager(defaultSessionManager);
        executorServiceSessionValidationScheduler.setThreadNamePrefix("test-");
        executorServiceSessionValidationScheduler.setSessionValidationInterval(1000L);
        executorServiceSessionValidationScheduler.enableSessionValidation();
        defaultSessionManager.create(session);
        Thread.sleep(2000L);
        session.stop();
        Thread.sleep(2000L);
        assertThat(defaultSessionManager.getActiveSessions()).isNotEmpty();
        assertThat(executorServiceSessionValidationScheduler.isEnabled()).isTrue();
    }

    @AfterEach
    public void tearDown() throws Exception {
        executorServiceSessionValidationScheduler.disableSessionValidation();
    }

    private static final class FakeDefaultSessionManager extends DefaultSessionManager {
        public void validateSessions() throws RuntimeException {
            throw new RuntimeException("Session test exception");
        }
    }
}
