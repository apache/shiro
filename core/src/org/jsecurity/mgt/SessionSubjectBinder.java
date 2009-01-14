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
package org.jsecurity.mgt;

import org.jsecurity.session.Session;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.Subject;

/**
 * Binds the Subject to the accessible Session in addition to the ThreadContext.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SessionSubjectBinder extends ThreadContextSubjectBinder {

    /**
     * The key that is used to store subject principals in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY = SessionSubjectBinder.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The key that is used to store whether or not the user is authenticated in the session.
     */
    public static final String AUTHENTICATED_SESSION_KEY = SessionSubjectBinder.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    @Override
    public void bind(Subject subject) {
        bindToSession(subject);
        super.bind(subject);
    }

    protected void bindToSession(Subject subject) {
        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            Session session = subject.getSession();
            session.setAttribute(PRINCIPALS_SESSION_KEY, principals);
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(PRINCIPALS_SESSION_KEY);
            }
        }

        if (subject.isAuthenticated()) {
            Session session = subject.getSession();
            session.setAttribute(AUTHENTICATED_SESSION_KEY, subject.isAuthenticated());
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(AUTHENTICATED_SESSION_KEY);
            }
        }
    }

    @Override
    public void unbind(Subject subject) {
        Session session = subject.getSession(false);
        if (session != null) {
            session.removeAttribute(PRINCIPALS_SESSION_KEY);
            session.removeAttribute(AUTHENTICATED_SESSION_KEY);
        }
        super.unbind(subject);
    }
}
