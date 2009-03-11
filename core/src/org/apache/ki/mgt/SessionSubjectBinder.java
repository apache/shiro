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
package org.apache.ki.mgt;

import org.apache.ki.session.Session;
import org.apache.ki.subject.PrincipalCollection;
import org.apache.ki.subject.Subject;


/**
 * Binds the Subject's state to the accessible {@link Session Session} in addition to the
 * {@link org.apache.ki.util.ThreadContext ThreadContext}
 * <p/>
 * The very notion of this class's existence might sound backwards:  typically a {@link Session Session} is something
 * that is created <em>after</em> a {@link Subject Subject} is acquired - for example by calling
 * <code>Subject.{@link Subject#getSession getSession()}</code>.  This might imply that a <code>Session</code> is also
 * therefore constrained to the 'owning' <code>Subject</code>'s lifecycle.
 * <p/>
 * However, in many environments, the <code>Subject</code> instance in memory is transient and exists only for the
 * duration of thread execution or during an incoming request in web environments.  The <code>Session</code> however
 * must be persistent over time since that is the very nature of the concept of a <code>Session</code>.  So, this
 * particular <code>SubjectBinder</code> implementation will save the relevant <code>Subject</code> state as
 * <code>Session</code> attributes to enable the <code>Subject</code> to be constructed on subsequent requests or
 * method invocations.
 * <p/>
 * This paradigm requires some framework code elsewhere to re-create the <code>Subject</code>:
 * <ol>
 * <li>A session ID would be acquired based on an incoming request or remote method invocation</li>
 * <li>The <code>Session</code> would be retrieved from the application's {@link SecurityManager SecurityManager}
 * (using the {@link org.apache.ki.session.mgt.SessionManager SessionManager} parent methods)</li>
 * <li>A <code>Subject</code> instance would be created based on the attributes found in that session</code>
 * <li>The constructed <code>Subject</code> would be 'bound' to the application for use during the request or method
 * invocation (say, bound to the processing thread)</li>
 * <li>The subject would then be accessible to the application for the duration of the thread</li>
 * <li>Any state changed to the subject at the end of the thread execution would be saved to back to the
 * <code>Session</code></li>
 * <li>The <code>Subject</code> instance wold be 'unbound' from the application/thread and garbage collected at the
 * end of request/thread execution, and a new one is created on the next request/method invocation as per step #1.</li>
 * </ol>
 * <p/>
 * Indeed this is exactly how JSecurity's default behavior works in enterprise server and web-based environments.  It is
 * enabled in the <code>JSecurityFilter</code> for web-based environments as well as remote-method-invocation-based
 * components for non-web environments.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SessionSubjectBinder extends ThreadContextSubjectBinder {

    //TODO - finish JavaDoc

    /**
     * The session key that is used to store subject principals.
     */
    public static final String PRINCIPALS_SESSION_KEY = SessionSubjectBinder.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The session key that is used to store whether or not the user is authenticated.
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
