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

import java.util.concurrent.Callable;

/**
 * @since 1.0
 */
public class SubjectCallable<V> implements Callable<V> {

    protected final ThreadStateManager threadStateManager;
    private final Callable<V> callable;

    public SubjectCallable(Subject subject, Callable<V> delegate) {
        this(new ThreadStateManager(subject), delegate);
    }

    protected SubjectCallable(ThreadStateManager manager, Callable<V> delegate) {
        if (manager == null) {
            throw new IllegalArgumentException("ThreadStateManager argument cannot be null.");
        }
        this.threadStateManager = manager;
        if (delegate == null) {
            throw new IllegalArgumentException("Callable delegate instance cannot be null.");
        }
        this.callable = delegate;
    }

    public V call() throws Exception {
        try {
            threadStateManager.bindThreadState();
            return doCall(this.callable);
        } finally {
            threadStateManager.restoreThreadState();
        }
    }

    protected V doCall(Callable<V> target) throws Exception {
        return target.call();
    }
}
