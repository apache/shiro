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
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Default {@code WebSubjectContext} implementation that provides for additional storage and retrieval of
 * a {@link ServletRequest} and {@link ServletResponse}.
 *
 * @since 1.0
 */
public class DefaultWebSubjectContext extends DefaultSubjectContext implements WebSubjectContext {

    private static final long serialVersionUID = 8188555355305827739L;

    private static final String SERVLET_REQUEST = DefaultWebSubjectContext.class.getName() + ".SERVLET_REQUEST";
    private static final String SERVLET_RESPONSE = DefaultWebSubjectContext.class.getName() + ".SERVLET_RESPONSE";

    public DefaultWebSubjectContext() {
    }

    public DefaultWebSubjectContext(WebSubjectContext context) {
        super(context);
    }

    @Override
    public String resolveHost() {
        String host = super.resolveHost();
        if (host == null) {
            ServletRequest request = resolveServletRequest();
            if (request != null) {
                host = request.getRemoteHost();
            }
        }
        return host;
    }

    public ServletRequest getServletRequest() {
        return getTypedValue(SERVLET_REQUEST, ServletRequest.class);
    }

    public void setServletRequest(ServletRequest request) {
        if (request != null) {
            put(SERVLET_REQUEST, request);
        }
    }

    public ServletRequest resolveServletRequest() {

        ServletRequest request = getServletRequest();

        //fall back on existing subject instance if it exists:
        if (request == null) {
            Subject existing = getSubject();
            if (existing instanceof WebSubject) {
                request = ((WebSubject) existing).getServletRequest();
            }
        }

        return request;
    }

    public ServletResponse getServletResponse() {
        return getTypedValue(SERVLET_RESPONSE, ServletResponse.class);
    }

    public void setServletResponse(ServletResponse response) {
        if (response != null) {
            put(SERVLET_RESPONSE, response);
        }
    }

    public ServletResponse resolveServletResponse() {

        ServletResponse response = getServletResponse();

        //fall back on existing subject instance if it exists:
        if (response == null) {
            Subject existing = getSubject();
            if (existing instanceof WebSubject) {
                response = ((WebSubject) existing).getServletResponse();
            }
        }

        return response;
    }
}
