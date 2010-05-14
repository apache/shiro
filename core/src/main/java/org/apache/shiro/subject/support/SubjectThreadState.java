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
 * @since 1.0
 */
public class SubjectThreadState implements ThreadState {

    private Map<Object,Object> originalResources;

    private final Subject subject;
    private final transient SecurityManager securityManager;

    public SubjectThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.subject = subject;

        SecurityManager originalSecurityManager = ThreadContext.getSecurityManager();

        //TODO - not an interface call (yuck)
        if (this.subject instanceof DelegatingSubject) {
            this.securityManager = ((DelegatingSubject) this.subject).getSecurityManager();
        } else {
            this.securityManager = originalSecurityManager;
        }
    }

    protected Subject getSubject() {
        return this.subject;
    }

    public void bind() {
        this.originalResources = ThreadContext.getResources();
        ThreadContext.remove();

        ThreadContext.bind(subject);
        if ( securityManager != null ) {
            ThreadContext.bind(securityManager);
        }
    }

    public void restore() {
        ThreadContext.remove();
        if ( !CollectionUtils.isEmpty(this.originalResources) ) {
            ThreadContext.setResources(this.originalResources);
        }
    }

    public void clear() {
        ThreadContext.remove();
    }
}
