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
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Test cases for the {@link SubjectAwareExecutor} implementation.
 *
 * @since 1.0
 */
public class SubjectAwareExecutorTest extends SecurityManagerTestSupport {

    @Test
    public void testExecute() {
        Executor targetMockExecutor = mock(Executor.class);
        final SubjectAwareExecutor executor = new SubjectAwareExecutor(targetMockExecutor);

        Runnable work = () -> System.out.println("Hello World");
        executor.execute(work);

        //* ensure the target Executor receives a SubjectRunnable instance that retains the subject identity:
        //(this is what verifies the test is valid):
        ArgumentCaptor<SubjectRunnable> subjectRunnableArgumentCaptor = ArgumentCaptor.forClass(SubjectRunnable.class);
        verify(targetMockExecutor).execute(subjectRunnableArgumentCaptor.capture());
        SubjectRunnable subjectRunnable = subjectRunnableArgumentCaptor.getValue();
        assertNotNull(subjectRunnable);
    }
}
