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
package org.apache.shiro.web;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.subject.WebSubjectBuilder;
import org.apache.shiro.web.subject.support.WebThreadStateManager;
import org.junit.After;
import org.junit.Before;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @since 1.0
 */
public abstract class AbstractWebSecurityManagerTest {

    private WebThreadStateManager threadState;

    @Before
    public void setup() {
        if (this.threadState != null) {
            this.threadState.clearAllThreadState();
        }
    }

    @After
    public void tearDown() {
        if (this.threadState != null) {
            this.threadState.clearAllThreadState();
        }
    }

    protected Subject newSubject(SecurityManager sm, ServletRequest request, ServletResponse response) {
        Subject subject = new WebSubjectBuilder(sm, request, response).build();
        this.threadState = new WebThreadStateManager(subject, request, response);
        this.threadState.bindThreadState();
        return subject;
    }

}
