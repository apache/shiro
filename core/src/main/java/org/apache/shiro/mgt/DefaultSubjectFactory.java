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
package org.apache.shiro.mgt;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.InetAuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.DelegatingSubject;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import java.net.InetAddress;
import java.util.Map;


/**
 * Default {@link SubjectFactory SubjectFactory} implementation that creates {@link DelegatingSubject DelegatingSubject}
 * instances.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class DefaultSubjectFactory implements SubjectFactory, SecurityManagerAware {

    private SecurityManager securityManager;

    public DefaultSubjectFactory() {
    }

    public DefaultSubjectFactory(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    @SuppressWarnings({"unchecked"})
    protected static <E> E getTypedValue(Map context, String key, Class<E> type) {
        E found = null;
        Object o = context.get(key);
        if (o != null) {
            if (!type.isAssignableFrom(o.getClass())) {
                String msg = "Invalid object found in context Map under key [" + key + "].  Expected type " +
                        "was [" + type.getName() + "], but the object under that key is of type " +
                        "[" + o.getClass().getName() + "].";
                throw new IllegalArgumentException(msg);
            }
            found = (E) o;
        }
        return found;
    }

    private void assertPrincipals(AuthenticationInfo info) {
        PrincipalCollection principals = info.getPrincipals();
        if (principals == null || principals.isEmpty()) {
            String msg = "AuthenticationInfo must have non null and non empty principals.";
            throw new IllegalArgumentException(msg);
        }
    }

    protected boolean isAuthenticationContext(Map context) {
        return context.containsKey(SubjectFactory.AUTHENTICATION_TOKEN);
    }

    protected static boolean isEmpty(PrincipalCollection principals) {
        return principals == null || principals.isEmpty();
    }

    protected PrincipalCollection getPrincipals(Map context, Session session) {
        PrincipalCollection principals = getTypedValue(context, SubjectFactory.PRINCIPALS, PrincipalCollection.class);

        if (isEmpty(principals)) {
            //check to see if they were just authenticated:
            AuthenticationInfo info = getTypedValue(context, SubjectFactory.AUTHENTICATION_INFO, AuthenticationInfo.class);
            if (info != null) {
                principals = info.getPrincipals();
            }
        }

        if (isEmpty(principals)) {
            Subject subject = getTypedValue(context, SubjectFactory.SUBJECT, Subject.class);
            if (subject != null) {
                principals = subject.getPrincipals();
            }
        }

        if (isEmpty(principals)) {
            //try the session:
            if (session != null) {
                principals = (PrincipalCollection) session.getAttribute(SessionSubjectBinder.PRINCIPALS_SESSION_KEY);
            }
        }

        return principals;
    }

    protected Session getSession(Map context) {
        Session session = getTypedValue(context, SubjectFactory.SESSION, Session.class);

        if (session == null) {
            //try the Subject if it exists:
            Subject existingSubject = getTypedValue(context, SubjectFactory.SUBJECT, Subject.class);
            if (existingSubject != null) {
                session = existingSubject.getSession(false);
            }
        }

        return session;
    }

    protected InetAddress getInetAddress(Map context, Session session) {
        InetAddress inet = getTypedValue(context, SubjectFactory.INET_ADDRESS, InetAddress.class);

        if (inet == null) {
            //check to see if there is an AuthenticationToken from which to retrieve it:
            AuthenticationToken token = getTypedValue(context, SubjectFactory.AUTHENTICATION_TOKEN, AuthenticationToken.class);
            if (token instanceof InetAuthenticationToken) {
                inet = ((InetAuthenticationToken) token).getInetAddress();
            }
        }

        if (inet == null) {
            if (session != null) {
                inet = session.getHostAddress();
            }
        }

        if (inet == null) {
            //fall back to the thread local if it exists:
            inet = ThreadContext.getInetAddress();
        }

        return inet;
    }

    protected boolean isAuthenticated(Map context, Session session) {
        Boolean authc = getTypedValue(context, SubjectFactory.AUTHENTICATED, Boolean.class);
        if (authc == null) {
            //see if there is an AuthenticationInfo object.  If so, the very presence of one indicates a successful
            //authentication attempt:
            AuthenticationInfo info = getTypedValue(context, SubjectFactory.AUTHENTICATION_INFO, AuthenticationInfo.class);
            authc = info != null;
        }
        if (!authc) {
            //fall back to a session check:
            if (session != null) {
                Boolean sessionAuthc = (Boolean) session.getAttribute(SessionSubjectBinder.AUTHENTICATED_SESSION_KEY);
                authc = sessionAuthc != null && sessionAuthc;
            }
        }
        return authc;
    }

    public Subject createSubject(Map context) {
        Session session = getSession(context);
        PrincipalCollection principals = getPrincipals(context, session);
        boolean authenticated = isAuthenticated(context, session);
        InetAddress inet = getInetAddress(context, session);
        return new DelegatingSubject(principals, authenticated, inet, session, getSecurityManager());
    }
}
