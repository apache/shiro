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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import java.util.concurrent.Executor;

/**
 * {@code Executor} implementation that will automatically first associate any argument
 * {@link Runnable} instances with the currently available {@link Subject} and then
 * dispatch the Subject-enabled runnable to an underlying delegate {@link Executor}
 * instance.
 * <p/>
 * This is a simplification for applications that want to execute code as the currently
 * executing {@code Subject} on another thread, but don't want or need to call the
 * {@link Subject#associateWith(Runnable)} method and dispatch to a Thread manually.  This
 * simplifies code and reduces Shiro dependencies across application source code.
 * <p/>
 * Consider this code that could be repeated in many places across an application:
 * <pre>
 * {@link Runnable Runnable} applicationWork = //instantiate or acquire Runnable from somewhere
 * {@link Subject Subject} subject = {@link SecurityUtils SecurityUtils}.{@link SecurityUtils#getSubject() getSubject()};
 * {@link Runnable Runnable} work = subject.{@link Subject#associateWith(Runnable) associateWith(applicationWork)};
 * {@link Executor anExecutor}.{@link Executor#execute(Runnable) execute(work)};
 * </pre>
 * Instead, if the {@code Executor} instance used in application code is an instance of this class (which delegates
 * to the target Executor that you want), all places in code like the above reduce to this:
 * <pre>
 * {@link Runnable Runnable} applicationWork = //instantiate or acquire Runnable from somewhere
 * {@link Executor anExecutor}.{@link Executor#execute(Runnable) execute(work)};
 * </pre>
 * Notice there is no use of the Shiro API in the 2nd code block, encouraging the principle of loose coupling across
 * your codebase.
 *
 * @see SubjectAwareExecutorService
 * @since 1.0
 */
public class SubjectAwareExecutor implements Executor {

    /**
     * The target Executor instance that will actually execute the subject-associated Runnable instances.
     */
    private Executor targetExecutor;

    public SubjectAwareExecutor() {
    }

    public SubjectAwareExecutor(Executor targetExecutor) {
        if (targetExecutor == null) {
            throw new NullPointerException("target Executor instance cannot be null.");
        }
        this.targetExecutor = targetExecutor;
    }

    /**
     * Returns the target Executor instance that will actually execute the subject-associated Runnable instances.
     *
     * @return target Executor instance that will actually execute the subject-associated Runnable instances.
     */
    public Executor getTargetExecutor() {
        return targetExecutor;
    }

    /**
     * Sets target Executor instance that will actually execute the subject-associated Runnable instances.
     *
     * @param targetExecutor the target Executor instance that will actually execute the subject-associated Runnable
     *                       instances.
     */
    public void setTargetExecutor(Executor targetExecutor) {
        this.targetExecutor = targetExecutor;
    }

    /**
     * Returns the currently Subject instance that should be associated with Runnable or Callable instances before
     * being dispatched to the target {@code Executor} instance.  This implementation merely defaults to returning
     * {@code SecurityUtils}.{@link SecurityUtils#getSubject() getSubject()}.
     *
     * @return the currently Subject instance that should be associated with Runnable or Callable instances before
     *         being dispatched to the target {@code Executor} instance.
     */
    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    /**
     * Utility method for subclasses to associate the argument {@code Runnable} with the currently executing subject
     * and then return the associated Runnable.  The default implementation merely defaults to
     * <pre>
     * Subject subject = {@link #getSubject() getSubject()};
     * return subject.{@link Subject#associateWith(Runnable) associateWith(r)};
     * </pre>
     *
     * @param r the argument runnable to be associated with the current subject
     * @return the associated runnable instance reflecting the current subject
     */
    protected Runnable associateWithSubject(Runnable r) {
        Subject subject = getSubject();
        return subject.associateWith(r);
    }

    /**
     * Executes the specified runnable by first associating it with the currently executing {@code Subject} and then
     * dispatches the associated Runnable to the underlying target {@link Executor} instance.
     *
     * @param command the runnable to associate with the currently executing subject and then to execute via the target
     *                {@code Executor} instance.
     */
    public void execute(Runnable command) {
        Runnable associated = associateWithSubject(command);
        getTargetExecutor().execute(associated);
    }
}
