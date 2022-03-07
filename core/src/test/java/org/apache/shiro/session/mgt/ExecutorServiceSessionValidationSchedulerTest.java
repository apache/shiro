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
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ExecutorServiceSessionValidationSchedulerTest {

    ExecutorServiceSessionValidationScheduler executorServiceSessionValidationScheduler;
    DefaultSessionManager defaultSessionManager;

    @Before
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
    public void timeoutSessionValidate() throws InterruptedException {
        Session session = new SimpleSession();
        session.setTimeout(2000L);
        defaultSessionManager.create(session);
        Thread.sleep(5000L);
        Assert.assertTrue(defaultSessionManager.getActiveSessions().isEmpty());
        Assert.assertTrue(executorServiceSessionValidationScheduler.isEnabled());
    }

    @Test
    public void stopSessionValidate() throws InterruptedException {
        Session session = new SimpleSession();
        session.setTimeout(10000L);
        defaultSessionManager.create(session);
        Thread.sleep(1000L);
        session.stop();
        Thread.sleep(3000L);
        Assert.assertTrue(defaultSessionManager.getActiveSessions().isEmpty());
        Assert.assertTrue(executorServiceSessionValidationScheduler.isEnabled());
    }

    @Test
    public void enableSessionValidation() throws InterruptedException {
        Assert.assertTrue(executorServiceSessionValidationScheduler.isEnabled());
        executorServiceSessionValidationScheduler.disableSessionValidation();
        Thread.sleep(2000L);
        Assert.assertFalse(executorServiceSessionValidationScheduler.isEnabled());
        executorServiceSessionValidationScheduler.enableSessionValidation();
        Thread.sleep(2000L);
        Assert.assertTrue(executorServiceSessionValidationScheduler.isEnabled());
    }

    @Test
    public void threadException() throws InterruptedException {
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
        Assert.assertFalse(defaultSessionManager.getActiveSessions().isEmpty());
        Assert.assertTrue(executorServiceSessionValidationScheduler.isEnabled());
    }

    @After
    public void tearDown() throws Exception {
        executorServiceSessionValidationScheduler.disableSessionValidation();
    }

    private class FakeDefaultSessionManager extends DefaultSessionManager {
        public void validateSessions() throws RuntimeException {
            throw new RuntimeException("Session test exception");
        }
    }
}
