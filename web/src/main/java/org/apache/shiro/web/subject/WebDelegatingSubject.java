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
package org.apache.shiro.web.subject;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.DelegatingSubject;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.subject.support.WebSubjectCallable;
import org.apache.shiro.web.subject.support.WebSubjectRunnable;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.concurrent.Callable;

/**
 * @since 1.0
 */
public class WebDelegatingSubject extends DelegatingSubject implements WebSubject {

    private final ServletRequest servletRequest;
    private final ServletResponse servletResponse;

    public WebDelegatingSubject(PrincipalCollection principals, boolean authenticated,
                                String host, Session session,
                                ServletRequest request, ServletResponse response,
                                SecurityManager securityManager) {
        super(principals, authenticated, host, session, securityManager);
        this.servletRequest = request;
        this.servletResponse = response;
    }

    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public ServletResponse getServletResponse() {
        return servletResponse;
    }

    @Override
    public <V> Callable<V> associateWith(Callable<V> callable) {
        return new WebSubjectCallable<V>(this, callable);
    }

    @Override
    public Runnable associateWith(Runnable runnable) {
        return new WebSubjectRunnable(this, runnable);
    }
}
