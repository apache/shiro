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
package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityUtils;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

import java.io.Serializable;

/**
 * A {@link RemoteInvocationFactory} that passes the session ID to the server via a
 * {@link RemoteInvocation} {@link RemoteInvocation#getAttribute(String) attribute}.
 * This factory is the client-side part of
 * the JSecurity Spring remoting invocation.  A {@link SecureRemoteInvocationExecutor} should
 * be used to export the server-side remote services to ensure that the appropriate
 * Subject and Session are bound to the remote thread during execution.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    private static final Log log = LogFactory.getLog(SecureRemoteInvocationFactory.class);

    public static final String SESSION_ID_KEY = Session.class.getName() + "_ID_KEY";

    private static final String SESSION_ID_SYSTEM_PROPERTY_NAME = "jsecurity.session.id";

    /**
     * Creates a {@link RemoteInvocation} with the current session ID as an
     * {@link RemoteInvocation#getAttribute(String) attribute}.
     *
     * @param methodInvocation the method invocation that the remote invocation should
     *                         be based on.
     * @return a remote invocation object containing the current session ID as an attribute.
     */
    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        Serializable sessionId = null;
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            Session session = subject.getSession(false);
            if (session != null) {
                sessionId = session.getId();
            }
        }

        if (sessionId == null) {
            if (log.isTraceEnabled()) {
                log.trace("No Session found for the currently executing subject via subject.getSession(false).  " +
                        "Attempting to revert back to the 'jsecurity.session.id' system property...");
            }
        }
        sessionId = System.getProperty(SESSION_ID_SYSTEM_PROPERTY_NAME);
        if (sessionId == null && log.isTraceEnabled()) {
            log.trace("No 'jsecurity.session.id' system property found.  Heuristics have been exhausted; " +
                    "RemoteInvocation will not contain a sessionId.");
        }
        RemoteInvocation ri = new RemoteInvocation(methodInvocation);
        if (sessionId != null) {
            ri.addAttribute(SESSION_ID_KEY, sessionId);
        }

        return ri;
    }
}
