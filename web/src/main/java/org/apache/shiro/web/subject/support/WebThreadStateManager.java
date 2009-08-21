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

import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.ThreadStateManager;
import org.apache.shiro.web.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * @since 1.0
 */
public class WebThreadStateManager extends ThreadStateManager {

    protected final ServletRequest originalRequest;
    protected final ServletResponse originalResponse;

    public WebThreadStateManager(Subject subject, ServletRequest request, ServletResponse response) {
        super(subject, WebUtils.getInetAddress(request));
        this.originalRequest = request;
        this.originalResponse = response;
    }

    public ServletRequest getOriginalRequest() {
        return originalRequest;
    }

    public ServletResponse getOriginalResponse() {
        return originalResponse;
    }

    @Override
    public void bindThreadState() {
        super.bindThreadState();
        WebUtils.bind(this.originalRequest);
        WebUtils.bind(this.originalResponse);
    }

    @Override
    public void restoreThreadState() {
        super.restoreThreadState();
        if (originalRequest == null) {
            WebUtils.unbindServletRequest();
        } else {
            WebUtils.bind(originalRequest);
        }
        if (originalResponse == null) {
            WebUtils.unbindServletResponse();
        } else {
            WebUtils.bind(originalResponse);
        }
    }
}
