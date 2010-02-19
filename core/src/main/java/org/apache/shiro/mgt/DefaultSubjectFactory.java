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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.HostAuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.DelegatingSubject;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;


/**
 * Default {@link SubjectFactory SubjectFactory} implementation that creates {@link DelegatingSubject DelegatingSubject}
 * instances.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class DefaultSubjectFactory implements SubjectFactory {

    private static transient final Logger log = LoggerFactory.getLogger(DefaultSubjectFactory.class);

    public DefaultSubjectFactory() {
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

    protected SecurityManager getSecurityManager(Map context) {
        SecurityManager securityManager = getTypedValue(context, SubjectFactory.SECURITY_MANAGER, SecurityManager.class);
        if (securityManager == null) {
            if (log.isDebugEnabled()) {
                log.debug("No SecurityManager available in subject context map.  " +
                        "Falling back to SecurityUtils.getSecurityManager() lookup.");
            }
            securityManager = SecurityUtils.getSecurityManager();
        }
        if (securityManager == null) {
            String msg = "No " + SecurityManager.class.getName() + " instance was available in the subject context " +
                    "via the " + SubjectFactory.SECURITY_MANAGER + " key.  " +
                    "This is required for this " + SubjectFactory.class.getSimpleName() + " implementation to " +
                    "function.";
            throw new IllegalStateException(msg);
        }
        return securityManager;
    }

    protected PrincipalCollection getPrincipals(Map context, Session session) {
        PrincipalCollection principals = getTypedValue(context, SubjectFactory.PRINCIPALS, PrincipalCollection.class);

        if (CollectionUtils.isEmpty(principals)) {
            //check to see if they were just authenticated:
            AuthenticationInfo info = getTypedValue(context, SubjectFactory.AUTHENTICATION_INFO, AuthenticationInfo.class);
            if (info != null) {
                principals = info.getPrincipals();
            }
        }

        if (CollectionUtils.isEmpty(principals)) {
            Subject subject = getTypedValue(context, SubjectFactory.SUBJECT, Subject.class);
            if (subject != null) {
                principals = subject.getPrincipals();
            }
        }

        if (CollectionUtils.isEmpty(principals)) {
            //try the session:
            if (session != null) {
                principals = (PrincipalCollection) session.getAttribute(SubjectFactory.PRINCIPALS_SESSION_KEY);
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

    protected String getHost(Map context, Session session) {
        String host = getTypedValue(context, SubjectFactory.HOST, String.class);

        if (host == null) {
            //check to see if there is an AuthenticationToken from which to retrieve it:
            AuthenticationToken token = getTypedValue(context, SubjectFactory.AUTHENTICATION_TOKEN, AuthenticationToken.class);
            if (token instanceof HostAuthenticationToken) {
                host = ((HostAuthenticationToken) token).getHost();
            }
        }

        if (host == null) {
            if (session != null) {
                host = session.getHost();
            }
        }

        return host;
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
                Boolean sessionAuthc = (Boolean) session.getAttribute(SubjectFactory.AUTHENTICATED_SESSION_KEY);
                authc = sessionAuthc != null && sessionAuthc;
            }
        }
        return authc;
    }

    public Subject createSubject(Map context) {
        SecurityManager securityManager = getSecurityManager(context);
        Session session = getSession(context);
        PrincipalCollection principals = getPrincipals(context, session);
        boolean authenticated = isAuthenticated(context, session);
        String host = getHost(context, session);
        return newSubjectInstance(principals, authenticated, host, session, securityManager);
    }

    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated, String host,
                                         Session session, SecurityManager securityManager) {
        return new DelegatingSubject(principals, authenticated, host, session, securityManager);
    }
}
