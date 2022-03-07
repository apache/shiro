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
package org.apache.shiro.concurrent;

import org.apache.shiro.subject.support.SubjectRunnable;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for the {@link SubjectAwareExecutorService} implementation.
 */
public class SubjectAwareExecutorServiceTest extends SecurityManagerTestSupport {

    @SuppressWarnings({"unchecked"})
    @Test
    public void testSubmitRunnable() {
        ExecutorService mockExecutorService = mock(ExecutorService.class);
        ArgumentCaptor<SubjectRunnable> captor = ArgumentCaptor.forClass(SubjectRunnable.class);
        when(mockExecutorService.submit(captor.capture())).thenReturn(new DummyFuture<>());

        final SubjectAwareExecutorService executor = new SubjectAwareExecutorService(mockExecutorService);

        Runnable testRunnable = () -> System.out.println("Hello World");

        executor.submit(testRunnable);
        SubjectRunnable subjectRunnable = captor.getValue();
        Assertions.assertNotNull(subjectRunnable);
    }

    private static class DummyFuture<V> implements Future<V> {

        @Override
        public boolean cancel(boolean b) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return true;
        }

        @Override
        public V get() throws InterruptedException, ExecutionException {
            return null;
        }

        @Override
        public V get(long l, TimeUnit timeUnit) throws InterruptedException, ExecutionException, TimeoutException {
            return null;
        }
    }
}
