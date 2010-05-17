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
package org.apache.shiro.web.subject.support;

import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.subject.WebSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Web-specific {@code SubjectThreadState} implementation that, in addition to the parent class's bind/unbind
 * behavior, also ensures that a {@link ServletRequest ServletRequest} and {@link ServletResponse ServletResponse}
 * pair are also bound/unbound as necessary.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class WebSubjectThreadState extends SubjectThreadState {

    private final ServletRequest request;
    private final ServletResponse response;

    /**
     * Creates a new {@code WebSubjectThreadState} instance, retaining the {@link WebSubject} argument's
     * {@link org.apache.shiro.web.subject.WebSubject#getServletRequest() servletRequest} and
     * {@link org.apache.shiro.web.subject.WebSubject#getServletResponse() servletResponse} in addition to any
     * state retained by the parent class's constructor.
     *
     * @param subject the {@link WebSubject} to bind as well as from which to acquire the
     *                {@code ServletRequest} and {@code ServletResponse} pair.
     */
    public WebSubjectThreadState(WebSubject subject) {
        super(subject);

        ServletRequest request = subject.getServletRequest();
        if (request == null) {
            request = WebUtils.getServletRequest();
        }
        this.request = request;

        ServletResponse response = subject.getServletResponse();
        if (response == null) {
            response = WebUtils.getServletResponse();
        }
        this.response = response;
    }

    /**
     * Calls {@code super.bind()} and then additionally binds the internal {@code ServletRequest} and
     * {@code ServletResponse} pair via
     * {@code WebUtils.}{@link WebUtils#bind(javax.servlet.ServletRequest) bind(ServletRequest)} and
     * {@code WebUtils.}{@link WebUtils#bind(javax.servlet.ServletResponse) bind(ServletResponse)}, respectively.
     */
    @Override
    public void bind() {
        super.bind();
        if (request != null) {
            WebUtils.bind(request);
        }
        if (response != null) {
            WebUtils.bind(response);
        }
    }
}
