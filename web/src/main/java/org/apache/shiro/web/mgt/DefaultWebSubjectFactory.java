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
package org.apache.shiro.web.mgt;

import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.subject.WebDelegatingSubject;
import org.apache.shiro.web.subject.WebSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.Map;

/**
 * A {@code SubjectFactory} implementation that creates {@link WebDelegatingSubject} instances.
 * <p/>
 * {@code WebDelegatingSubject} instances are required if Request/Response objects are to be maintained across
 * threads when using the {@code Subject} {@link Subject#associateWith(java.util.concurrent.Callable) createCallable}
 * and {@link Subject#associateWith(Runnable) createRunnable} methods.
 *
 * @see #newSubjectInstance(org.apache.shiro.subject.PrincipalCollection, boolean, java.net.InetAddress, org.apache.shiro.session.Session, org.apache.shiro.mgt.SecurityManager)
 * @since 1.0
 */
public class DefaultWebSubjectFactory extends DefaultSubjectFactory {

    public DefaultWebSubjectFactory() {
        super();
    }

    public DefaultWebSubjectFactory(SecurityManager securityManager) {
        super(securityManager);
    }

    protected ServletRequest getServletRequest(Map context) {
        ServletRequest request = getTypedValue(context, SubjectFactory.SERVLET_REQUEST, ServletRequest.class);

        //fall back on existing subject instance if it exists:
        if (request == null) {
            Subject existing = getTypedValue(context, SubjectFactory.SUBJECT, Subject.class);
            if (existing instanceof WebSubject) {
                request = ((WebSubject) existing).getServletRequest();
            }
        }
        //last resort - try the thread-local (TODO - remove this if possible):
        if (request == null) {
            request = WebUtils.getServletRequest();
        }

        if (request == null) {
            throw new IllegalStateException("ServletRequest is not available!  A ServletRequest must be present " +
                    "in either the Subject context map, on an existing WebSubject or via the thread context.  This " +
                    "exception is probably indicative of an erroneous application configuration.");
        }
        return request;
    }

    protected ServletResponse getServletResponse(Map context) {
        ServletResponse response = getTypedValue(context, SubjectFactory.SERVLET_RESPONSE, ServletResponse.class);

        //fall back on existing subject instance if it exists:
        if (response == null) {
            Subject existing = getTypedValue(context, SubjectFactory.SUBJECT, Subject.class);
            if (existing instanceof WebSubject) {
                response = ((WebSubject) existing).getServletResponse();
            }
        }

        //last resort - try the thread-local (TODO - remove this if possible):
        if (response == null) {
            response = WebUtils.getServletResponse();
        }

        if (response == null) {
            throw new IllegalStateException("ServletResponse is not available!  A ServletResponse must be present " +
                    "in either the Subject context map, on an existing WebSubject or via the thread context.  This " +
                    "exception is probably indicative of an erroneous application configuration.");
        }

        return response;
    }

    @Override
    protected InetAddress getInetAddress(Map context, Session session) {
        InetAddress inet = super.getInetAddress(context, session);
        if (inet == null) {
            ServletRequest request = getServletRequest(context);
            inet = WebUtils.getInetAddress(request);
        }
        return inet;
    }

    public Subject createSubject(Map context) {
        Session session = getSession(context);
        PrincipalCollection principals = getPrincipals(context, session);
        boolean authenticated = isAuthenticated(context, session);
        InetAddress inet = getInetAddress(context, session);
        ServletRequest request = getServletRequest(context);
        ServletResponse response = getServletResponse(context);
        return newSubjectInstance(principals, authenticated, inet, session, request, response, getSecurityManager());
    }

    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated,
                                         InetAddress inet, Session session,
                                         ServletRequest request, ServletResponse response,
                                         SecurityManager securityManager) {
        return new WebDelegatingSubject(principals, authenticated, inet, session, request, response, securityManager);
    }
}
