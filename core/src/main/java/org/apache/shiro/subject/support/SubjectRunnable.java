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
 * A {@code SubjectRunnable} ensures that a target/delegate {@link Runnable Runnable} will execute such that any
 * call to {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()} during the
 * {@code Runnable}'s execution will return the associated {@code Subject} instance.  The {@code SubjectRunnable}
 * instance can be run on any thread (the current thread or asynchronously on another thread) and the
 * {@code SecurityUtils.getSubject()} call will still work properly.  This implementation also guarantees that Shiro's
 * thread state will be identical before and after execution to ensure threads remain clean in any thread-pooled
 * environment.
 * <p/>
 * When instances of this class {@link Runnable#run() run()}, the following occurs:
 * <ol>
 * <li>The Subject and any of its associated thread state is first bound to the thread that executes the
 * {@code Runnable}.</li>
 * <li>The delegate/target {@code Runnable} is {@link #doRun(Runnable) run}</li>
 * <li>Any previous thread state that might have existed before the {@code Subject} was bound is fully restored</li>
 * </ol>
 * <p/>
 *
 * <h3>Usage</h3>
 *
 * This is typically considered a support class and is not often directly referenced.  Most people prefer to use
 * the {@code Subject.}{@link Subject#execute(Runnable) execute} or
 * {@code Subject.}{@link Subject#associateWith(Runnable) associateWith} methods, which transparently perform the
 * necessary association logic.
 * <p/>
 * An even more convenient alternative is to use a
 * {@link org.apache.shiro.concurrent.SubjectAwareExecutor SubjectAwareExecutor}, which transparently uses
 * instances of this class but does not require referencing Shiro's API at all.
 *
 * @see Subject#associateWith(Runnable)
 * @see org.apache.shiro.concurrent.SubjectAwareExecutor SubjectAwareExecutor
 * @since 1.0
 */
public class SubjectRunnable implements Runnable {

    protected final ThreadState threadState;
    private final Runnable runnable;

    /**
     * Creates a new {@code SubjectRunnable} that, when executed, will execute the target {@code delegate}, but
     * guarantees that it will run associated with the specified {@code Subject}.
     *
     * @param subject  the Subject to associate with the delegate's execution.
     * @param delegate the runnable to run.
     */
    public SubjectRunnable(Subject subject, Runnable delegate) {
        this(new SubjectThreadState(subject), delegate);
    }

    /**
     * Creates a new {@code SubjectRunnable} that, when executed, will perform thread state
     * {@link ThreadState#bind binding} and guaranteed {@link ThreadState#restore restoration} before and after the
     * {@link Runnable Runnable}'s execution, respectively.
     *
     * @param threadState the thread state to bind and unbind before and after the runnable's execution.
     * @param delegate    the delegate {@code Runnable} to execute when this instance is {@link #run() run()}.
     * @throws IllegalArgumentException if either the {@code ThreadState} or {@link Runnable} arguments are {@code null}.
     */
    protected SubjectRunnable(ThreadState threadState, Runnable delegate) throws IllegalArgumentException {
        if (threadState == null) {
            throw new IllegalArgumentException("ThreadState argument cannot be null.");
        }
        this.threadState = threadState;
        if (delegate == null) {
            throw new IllegalArgumentException("Runnable argument cannot be null.");
        }
        this.runnable = delegate;
    }

    /**
     * {@link ThreadState#bind Bind}s the Subject thread state, executes the target {@code Runnable} and then guarantees
     * the previous thread state's {@link ThreadState#restore restoration}:
     * <pre>
     * try {
     *     threadState.{@link ThreadState#bind bind()};
     *     {@link #doRun doRun}(targetRunnable);
     * } finally {
     *     threadState.{@link ThreadState#restore restore()}
     * }
     * </pre>
     */
    public void run() {
        try {
            threadState.bind();
            doRun(this.runnable);
        } finally {
            threadState.restore();
        }
    }

    /**
     * Simply calls the target {@link Runnable Runnable}'s {@link Runnable#run run()} method.
     *
     * @param runnable the target runnable to run.
     */
    protected void doRun(Runnable runnable) {
        runnable.run();
    }
}
