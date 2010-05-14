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
 * @since 1.0
 */
public class WebSubjectThreadState extends SubjectThreadState {

    private final ServletRequest request;
    private final ServletResponse response;

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
