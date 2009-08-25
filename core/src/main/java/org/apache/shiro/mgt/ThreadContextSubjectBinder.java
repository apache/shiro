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
package org.apache.shiro.mgt;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Associates a {@link Subject Subject} instance to the currently executing thread via the {
 *
 * @author Les Hazlewood
 * @link ThreadContext ThreadContext} to ensure that the <code>Subject</code> is accessible to any caller during
 * thread execution.
 * @see org.apache.shiro.SecurityUtils#getSubject SecurityUtils.getSubject()
 * @since 1.0
 */
public class ThreadContextSubjectBinder implements SubjectBinder {

    private static final Logger log = LoggerFactory.getLogger(ThreadContextSubjectBinder.class);

    /**
     * This implementation returns the {@link Subject Subject} from the {@link ThreadContext ThreadContext}.
     *
     * @return the {@link Subject Subject} in the {@link ThreadContext ThreadContext}
     */
    public Subject getSubject() {
        return ThreadContext.getSubject();
    }

    /**
     * Associates the specified subject to the currently executing thread via the {@link ThreadContext ThreadContext}.
     *
     * @param subject the subject to associate to the currently executing thread.
     */
    public void bind(Subject subject) {
        if (log.isTraceEnabled()) {
            log.trace("Binding Subject [" + subject + "] to a thread local...");
        }
        ThreadContext.bind(subject);
    }

    /**
     * Removes the specified Subject instance from the currently executing thread by removing it from the
     * {@link ThreadContext ThreadContext}
     *
     * @param subject the <code>Subject</code> instance to unbind from the currently executing thread.
     */
    public void unbind(Subject subject) {
        ThreadContext.unbindSubject();
    }
}
