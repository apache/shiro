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

import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Same concept as the {@link SubjectAwareExecutorService} but additionally supports the
 * {@link ScheduledExecutorService} interface.
 */
public abstract class SubjectAwareScheduledExecutorService extends SubjectAwareExecutorService implements ScheduledExecutorService {

    private ScheduledExecutorService targetScheduledExecutorService;

    public SubjectAwareScheduledExecutorService() {
    }

    public SubjectAwareScheduledExecutorService(ScheduledExecutorService target) {
        setTargetScheduledExecutorService(target);
    }

    public ScheduledExecutorService getTargetScheduledExecutorService() {
        return targetScheduledExecutorService;
    }

    public void setTargetScheduledExecutorService(ScheduledExecutorService targetScheduledExecutorService) {
        this.targetScheduledExecutorService = targetScheduledExecutorService;
        setTargetExecutorService(targetScheduledExecutorService);
    }

    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.schedule(work, delay, unit);
    }

    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        Callable<V> work = associateWithSubject(callable);
        return this.targetScheduledExecutorService.schedule(work, delay, unit);
    }

    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.scheduleAtFixedRate(work, initialDelay, period, unit);
    }

    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        Runnable work = associateWithSubject(command);
        return this.targetScheduledExecutorService.scheduleWithFixedDelay(work, initialDelay, delay, unit);
    }
}
