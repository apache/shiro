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
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.DelegatingSubject;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;

import java.io.Serializable;

/**
 * @since 1.0
 */
public class SubjectThreadState implements ThreadState {

    private Subject originalSubject;
    private Serializable originalSessionId;
    private transient SecurityManager originalSecurityManager;

    private final Serializable sessionId;
    private final Subject subject;
    private final transient SecurityManager securityManager;

    public SubjectThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.originalSubject = ThreadContext.getSubject();
        this.subject = subject;

        this.originalSecurityManager = ThreadContext.getSecurityManager();

        //TODO - not an interface call (yuck)
        if (this.subject instanceof DelegatingSubject) {
            this.securityManager = ((DelegatingSubject) this.subject).getSecurityManager();
        } else {
            this.securityManager = this.originalSecurityManager;
        }

        Session session = this.subject.getSession(false);

        this.originalSessionId = ThreadContext.getSessionId();
        if (session != null) {
            this.sessionId = session.getId();
        } else {
            this.sessionId = this.originalSessionId;
        }
    }

    protected Subject getSubject() {
        return this.subject;
    }

    public void bind() {
        this.originalSessionId = ThreadContext.getSessionId();
        this.originalSubject = ThreadContext.getSubject();
        this.originalSecurityManager = ThreadContext.getSecurityManager();

        if (sessionId == null) {
            ThreadContext.unbindSessionId();
        } else {
            ThreadContext.bindSessionId(sessionId);
        }
        ThreadContext.bind(subject);
        if (securityManager == null) {
            ThreadContext.unbindSecurityManager();
        } else {
            ThreadContext.bind(securityManager);
        }
    }

    public void restore() {
        if (originalSessionId == null) {
            ThreadContext.unbindSessionId();
        } else {
            ThreadContext.bindSessionId(originalSessionId);
        }
        if (originalSubject == null) {
            ThreadContext.unbindSubject();
        } else {
            ThreadContext.bind(originalSubject);
        }
        if (originalSecurityManager == null) {
            ThreadContext.unbindSecurityManager();
        } else {
            ThreadContext.bind(originalSecurityManager);
        }
    }

    public void clear() {
        ThreadContext.clear();
    }
}
