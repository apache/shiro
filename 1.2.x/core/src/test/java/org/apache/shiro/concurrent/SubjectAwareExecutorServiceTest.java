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
import org.junit.Test;

import java.util.concurrent.*;

import static org.easymock.EasyMock.*;

/**
 * Test cases for the {@link SubjectAwareExecutorService} implementation.
 */
public class SubjectAwareExecutorServiceTest extends SecurityManagerTestSupport {

    @SuppressWarnings({"unchecked"})
    @Test
    public void testSubmitRunnable() {
        ExecutorService mockExecutorService = createNiceMock(ExecutorService.class);
        expect(mockExecutorService.submit(isA(SubjectRunnable.class))).andReturn(new DummyFuture());
        replay(mockExecutorService);

        final SubjectAwareExecutorService executor = new SubjectAwareExecutorService(mockExecutorService);

        Runnable testRunnable = new Runnable() {
            public void run() {
                System.out.println("Hello World");
            }
        };

        executor.submit(testRunnable);
        verify(mockExecutorService);
    }

    private class DummyFuture<V> implements Future<V> {

        public boolean cancel(boolean b) {
            return false;
        }

        public boolean isCancelled() {
            return false;
        }

        public boolean isDone() {
            return true;
        }

        public V get() throws InterruptedException, ExecutionException {
            return null;
        }

        public V get(long l, TimeUnit timeUnit) throws InterruptedException, ExecutionException, TimeoutException {
            return null;
        }
    }
}
