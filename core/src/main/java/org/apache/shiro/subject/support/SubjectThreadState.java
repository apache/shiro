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

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;

import java.util.Map;

/**
 * Manages thread-state for {@link Subject Subject} access (supporting
 * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()} calls)
 * during a thread's execution.
 * <p/>
 * The {@link #bind bind} method will bind a {@link Subject} and a
 * {@link org.apache.shiro.mgt.SecurityManager SecurityManager} to the {@link ThreadContext} so they can be retrieved
 * from the {@code ThreadContext} later by any
 * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()} calls that might occur during
 * the thread's execution.
 *
 * @since 1.0
 */
public class SubjectThreadState implements ThreadState {

    private Map<Object, Object> originalResources;

    private final Subject subject;
    private transient SecurityManager securityManager;

    /**
     * Creates a new {@code SubjectThreadState} that will bind and unbind the specified {@code Subject} to the
     * thread
     *
     * @param subject the {@code Subject} instance to bind and unbind from the {@link ThreadContext}.
     */
    public SubjectThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.subject = subject;

        SecurityManager securityManager = null;
        if ( subject instanceof DelegatingSubject) {
            securityManager = ((DelegatingSubject)subject).getSecurityManager();
        }
        if ( securityManager == null) {
            securityManager = ThreadContext.getSecurityManager();
        }
        this.securityManager = securityManager;
    }

    /**
     * Returns the {@code Subject} instance managed by this {@code ThreadState} implementation.
     *
     * @return the {@code Subject} instance managed by this {@code ThreadState} implementation.
     */
    protected Subject getSubject() {
        return this.subject;
    }

    /**
     * Binds a {@link Subject} and {@link org.apache.shiro.mgt.SecurityManager SecurityManager} to the
     * {@link ThreadContext} so they can be retrieved later by any
     * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()} calls that might occur
     * during the thread's execution.
     * <p/>
     * Prior to binding, the {@code ThreadContext}'s existing {@link ThreadContext#getResources() resources} are
     * retained so they can be restored later via the {@link #restore restore} call.
     */
    public void bind() {
        SecurityManager securityManager = this.securityManager;
        if ( securityManager == null ) {
            //try just in case the constructor didn't find one at the time:
            securityManager = ThreadContext.getSecurityManager();
        }
        this.originalResources = ThreadContext.getResources();
        ThreadContext.remove();

        ThreadContext.bind(this.subject);
        if (securityManager != null) {
            ThreadContext.bind(securityManager);
        }
    }

    /**
     * {@link ThreadContext#remove Remove}s all thread-state that was bound by this instance.  If any previous
     * thread-bound resources existed prior to the {@link #bind bind} call, they are restored back to the
     * {@code ThreadContext} to ensure the thread state is exactly as it was before binding.
     */
    public void restore() {
        ThreadContext.remove();
        if (!CollectionUtils.isEmpty(this.originalResources)) {
            ThreadContext.setResources(this.originalResources);
        }
    }

    /**
     * Completely {@link ThreadContext#remove removes} the {@code ThreadContext} state.  Typically this method should
     * only be called in special cases - it is more 'correct' to {@link #restore restore} a thread to its previous
     * state than to clear it entirely.
     */
    public void clear() {
        ThreadContext.remove();
    }
}
