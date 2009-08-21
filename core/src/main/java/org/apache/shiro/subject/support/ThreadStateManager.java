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

import java.io.Serializable;
import java.net.InetAddress;

/**
 * @since 1.0
 */
public class ThreadStateManager {

    private final Subject originalSubject;
    private final InetAddress originalInetAddress;
    private final Serializable originalSessionId;
    private final transient SecurityManager originalSecurityManager;

    public ThreadStateManager(Subject subject) {
        this(subject, ThreadContext.getInetAddress());
    }

    protected ThreadStateManager(Subject subject, InetAddress inetAddressFallback) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.originalSubject = subject;

        //TODO - not an interface call (yuck)
        if (this.originalSubject instanceof DelegatingSubject) {
            this.originalSecurityManager = ((DelegatingSubject) this.originalSubject).getSecurityManager();
        } else {
            this.originalSecurityManager = ThreadContext.getSecurityManager();
        }

        Session session = this.originalSubject.getSession(false);

        InetAddress inet = null;
        if (session != null) {
            inet = session.getHostAddress();
        }
        if (inet == null) {
            inet = inetAddressFallback;
        }
        this.originalInetAddress = inet;

        if (session != null) {
            this.originalSessionId = session.getId();
        } else {
            this.originalSessionId = ThreadContext.getSessionId();
        }
    }

    public InetAddress getOriginalInetAddress() {
        return originalInetAddress;
    }

    public SecurityManager getOriginalSecurityManager() {
        return originalSecurityManager;
    }

    public Serializable getOriginalSessionId() {
        return originalSessionId;
    }

    public Subject getOriginalSubject() {
        return originalSubject;
    }

    public void bindThreadState() {
        ThreadContext.bind(this.originalSecurityManager);
        ThreadContext.bind(this.originalSubject);
        ThreadContext.bind(this.originalInetAddress);
        ThreadContext.bindSessionId(this.originalSessionId);
    }

    public void restoreThreadState() {
        if (originalSubject == null) {
            ThreadContext.unbindSubject();
        } else {
            ThreadContext.bind(originalSubject);
        }
        if (originalInetAddress == null) {
            ThreadContext.unbindInetAddress();
        } else {
            ThreadContext.bind(originalInetAddress);
        }
        if (originalSecurityManager == null) {
            ThreadContext.unbindSecurityManager();
        } else {
            ThreadContext.bind(originalSecurityManager);
        }
        if (originalSessionId == null) {
            ThreadContext.unbindSessionId();
        } else {
            ThreadContext.bindSessionId(originalSessionId);
        }
    }

    public void clearAllThreadState() {
        ThreadContext.clear();
    }
}
