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

import java.util.concurrent.Callable;

/**
 * A {@code SubjectCallable} associates a {@link Subject Subject} with a target/delegate
 * {@link Callable Callable} to ensure proper {@code Subject} thread-state management when the {@code Callable} executes.
 * This ensures that any calls to {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}
 * during the target {@code Callable}'s execution still work correctly even if the {@code Callable} executes on a
 * different thread than the one that created it.  This allows {@code Subject} access during asynchronous operations.
 * <p/>
 * When instances of this class execute (typically via a {@link java.util.concurrent.ExecutorService ExecutorService}),
 * the following occurs:
 * <ol>
 * <li>The specified Subject any of its associated thread state is first bound to the thread that executes the
 * {@code Callable}.</li>
 * <li>The delegate/target {@code Callable} is {@link java.util.concurrent.Callable#call() executed}</li>
 * <li>The previous thread state that might have existed before the {@code Subject} was bound is fully restored</li>
 * </ol>
 * <p/>
 * This behavior ensures that the thread that executes this {@code Callable}, which is often a different thread than
 * the one that created the instance, retains a {@code Subject} to support {@code SecurityUtils.getSubject()}
 * invocations. It also guarantees that the running thread remains 'clean' in any thread-pooled environments.
 *
 * <h3>Usage</h3>
 *
 * This is typically considered a support class and is not often directly referenced.  Most people prefer to use
 * the {@code Subject.}{@link Subject#associateWith(Callable) associateWith} method, which will automatically return
 * an instance of this class.
 * <p/>
 * An even more convenient alternative is to use a
 * {@link org.apache.shiro.concurrent.SubjectAwareExecutorService SubjectAwareExecutorService}, which
 * transparently uses instances of this class.
 *
 * @see Subject#associateWith(Callable)
 * @see org.apache.shiro.concurrent.SubjectAwareExecutorService SubjectAwareExecutorService
 * @since 1.0
 */
public class SubjectCallable<V> implements Callable<V> {

    protected final ThreadState threadState;
    private final Callable<V> callable;

    public SubjectCallable(Subject subject, Callable<V> delegate) {
        this(new SubjectThreadState(subject), delegate);
    }

    protected SubjectCallable(ThreadState threadState, Callable<V> delegate) {
        if (threadState == null) {
            throw new IllegalArgumentException("ThreadState argument cannot be null.");
        }
        this.threadState = threadState;
        if (delegate == null) {
            throw new IllegalArgumentException("Callable delegate instance cannot be null.");
        }
        this.callable = delegate;
    }

    public V call() throws Exception {
        try {
            threadState.bind();
            return doCall(this.callable);
        } finally {
            threadState.restore();
        }
    }

    protected V doCall(Callable<V> target) throws Exception {
        return target.call();
    }
}
