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

import java.util.concurrent.Executor;

import static org.easymock.EasyMock.*;

/**
 * Test cases for the {@link SubjectAwareExecutor} implementation.
 *
 * @since 1.0
 */
public class SubjectAwareExecutorTest extends SecurityManagerTestSupport {

    @Test
    public void testExecute() {
        Executor targetMockExecutor = createNiceMock(Executor.class);
        //* ensure the target Executor receives a SubjectRunnable instance that retains the subject identity:
        //(this is what verifies the test is valid):
        targetMockExecutor.execute(isA(SubjectRunnable.class));
        replay(targetMockExecutor);

        final SubjectAwareExecutor executor = new SubjectAwareExecutor(targetMockExecutor);

        Runnable work = new Runnable() {
            public void run() {
                System.out.println("Hello World");
            }
        };
        executor.execute(work);

        verify(targetMockExecutor);
    }
}
