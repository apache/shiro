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
package org.apache.shiro.subject.support;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadState;

/**
 * @since 1.0
 */
public class SubjectRunnable implements Runnable {

    protected final ThreadState threadState;
    private final Runnable runnable;

    public SubjectRunnable(Subject subject, Runnable delegate) {
        this(new SubjectThreadState(subject), delegate);
    }

    protected SubjectRunnable(ThreadState threadState, Runnable delegate) {
        if (threadState == null) {
            throw new IllegalArgumentException("ThreadState argument cannot be null.");
        }
        this.threadState = threadState;
        if (delegate == null) {
            throw new IllegalArgumentException("Runnable argument cannot be null.");
        }
        this.runnable = delegate;
    }

    public void run() {
        try {
            threadState.bind();
            doRun(this.runnable);
        } finally {
            threadState.restore();
        }
    }

    protected void doRun(Runnable runnable) {
        runnable.run();
    }
}
