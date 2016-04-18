/*
 * Copyright 2016 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.subject.support;

import java.util.Map;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;

/**
 *
 * @author mnn
 */
public class OSGiThreadState implements ThreadState{

    
    private Map<Object, Object> originalResources;

    private final Subject subject;

    /**
     * Creates a new {@code OSGiThreadState} that will bind and unbind the specified {@code Subject} to the
     * thread
     *
     * @param subject the {@code Subject} instance to bind and unbind from the {@link ThreadContext}.
     */
    public OSGiThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.subject = subject;
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
     * Binds a {@link Subject} to the
     * {@link ThreadContext} so they can be retrieved later by any
     * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()} calls that might occur
     * during the thread's execution.
     * <p/>
     * Prior to binding, the {@code ThreadContext}'s existing {@link ThreadContext#getResources() resources} are
     * retained so they can be restored later via the {@link #restore restore} call.
     */
    public void bind() {
        this.originalResources = ThreadContext.getResources();
        ThreadContext.remove();

        ThreadContext.bind(this.subject);
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