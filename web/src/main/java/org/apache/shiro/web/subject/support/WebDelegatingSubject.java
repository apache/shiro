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

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.session.mgt.DefaultWebSessionContext;
import org.apache.shiro.web.session.mgt.WebSessionContext;
import org.apache.shiro.web.subject.WebSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Default {@link WebSubject WebSubject} implementation that additional ensures the ability to retain a
 * servlet request/response pair to be used by internal shiro components as necessary during the request execution.
 *
 * @since 1.0
 */
public class WebDelegatingSubject extends DelegatingSubject implements WebSubject {

    private static final long serialVersionUID = -1655724323350159250L;

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
    protected SessionContext createSessionContext() {
        WebSessionContext wsc = new DefaultWebSessionContext();
        String host = getHost();
        if (StringUtils.hasText(host)) {
            wsc.setHost(host);
        }
        wsc.setServletRequest(this.servletRequest);
        wsc.setServletResponse(this.servletResponse);
        return wsc;
    }
}
