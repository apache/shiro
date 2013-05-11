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

import org.apache.shiro.subject.Subject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.*;

/**
 * {@code ExecutorService} implementation that will automatically first associate any argument
 * {@link Runnable} or {@link Callable} instances with the {@link #getSubject currently available subject} and then
 * dispatch the Subject-enabled runnable or callable to an underlying delegate
 * {@link java.util.concurrent.ExecutorService ExecutorService} instance.  The principle is the same as the
 * parent {@link SubjectAwareExecutor} class, but enables the richer {@link ExecutorService} API.
 * <p/>
 * This is a simplification for applications that want to execute code as the currently
 * executing {@code Subject} on another thread, but don't want or need to call the
 * {@link Subject#associateWith(Runnable)} or {@link Subject#associateWith(Callable)} methods and dispatch them to a
 * Thread manually.  This simplifies code and reduces Shiro dependencies across application source code.
 * <p/>
 * Consider this code that could be repeated in many places across an application:
 * <pre>
 * {@link Callable Callable} applicationWork = //instantiate or acquire Callable from somewhere
 * {@link Subject Subject} subject = {@link org.apache.shiro.SecurityUtils SecurityUtils}.{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()};
 * {@link Callable Callable} work = subject.{@link Subject#associateWith(Callable) associateWith(applicationWork)};
 * {@link ExecutorService anExecutorService}.{@link ExecutorService#submit(Callable) submit(work)};
 * </pre>
 * Instead, if the {@code ExecutorService} instance used at runtime is an instance of this class
 * (which delegates to the target ExecutorService that you want), all places in code like the above reduce to this:
 * <pre>
 * {@link Callable Callable} applicationWork = //instantiate or acquire Callable from somewhere
 * {@link ExecutorService anExecutorService}.{@link ExecutorService#submit(Callable) submit(work)};
 * </pre>
 * Notice there is no use of the Shiro API in the 2nd code block, encouraging the principle of loose coupling across
 * your codebase.
 *
 * @since 1.0
 */
public class SubjectAwareExecutorService extends SubjectAwareExecutor implements ExecutorService {

    private ExecutorService targetExecutorService;

    public SubjectAwareExecutorService() {
    }

    public SubjectAwareExecutorService(ExecutorService target) {
        setTargetExecutorService(target);
    }

    public ExecutorService getTargetExecutorService() {
        return targetExecutorService;
    }

    public void setTargetExecutorService(ExecutorService targetExecutorService) {
        super.setTargetExecutor(targetExecutorService);
        this.targetExecutorService = targetExecutorService;
    }

    @Override
    public void setTargetExecutor(Executor targetExecutor) {
        if (!(targetExecutor instanceof ExecutorService)) {
            String msg = "The " + getClass().getName() + " implementation only accepts " +
                    ExecutorService.class.getName() + " target instances.";
            throw new IllegalArgumentException(msg);
        }
        super.setTargetExecutor(targetExecutor);
    }

    public void shutdown() {
        this.targetExecutorService.shutdown();
    }

    public List<Runnable> shutdownNow() {
        return this.targetExecutorService.shutdownNow();
    }

    public boolean isShutdown() {
        return this.targetExecutorService.isShutdown();
    }

    public boolean isTerminated() {
        return this.targetExecutorService.isTerminated();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return this.targetExecutorService.awaitTermination(timeout, unit);
    }

    protected <T> Callable<T> associateWithSubject(Callable<T> task) {
        Subject subject = getSubject();
        return subject.associateWith(task);
    }

    public <T> Future<T> submit(Callable<T> task) {
        Callable<T> work = associateWithSubject(task);
        return this.targetExecutorService.submit(work);
    }

    public <T> Future<T> submit(Runnable task, T result) {
        Runnable work = associateWithSubject(task);
        return this.targetExecutorService.submit(work, result);
    }

    public Future<?> submit(Runnable task) {
        Runnable work = associateWithSubject(task);
        return this.targetExecutorService.submit(work);
    }

    protected <T> Collection<Callable<T>> associateWithSubject(Collection<? extends Callable<T>> tasks) {
        Collection<Callable<T>> workItems = new ArrayList<Callable<T>>(tasks.size());
        for (Callable<T> task : tasks) {
            Callable<T> work = associateWithSubject(task);
            workItems.add(work);
        }
        return workItems;
    }

    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks) throws InterruptedException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAll(workItems);
    }

    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAll(workItems, timeout, unit);
    }

    public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAny(workItems);
    }

    public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException {
        Collection<Callable<T>> workItems = associateWithSubject(tasks);
        return this.targetExecutorService.invokeAny(workItems, timeout, unit);
    }
}
