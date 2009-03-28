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
package org.apache.ki.spring.remoting;

import java.io.Serializable;
import java.net.InetAddress;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.ki.SecurityUtils;
import org.apache.ki.util.ThreadContext;
import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.SessionManager;
import org.apache.ki.subject.Subject;


/**
 * A {@link RemoteInvocationFactory} that passes the session ID to the server via a
 * {@link RemoteInvocation} {@link RemoteInvocation#getAttribute(String) attribute}.
 * This factory is the client-side part of
 * the Ki Spring remoting invocation.  A {@link SecureRemoteInvocationExecutor} should
 * be used to export the server-side remote services to ensure that the appropriate
 * Subject and Session are bound to the remote thread during execution.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    private static final Logger log = LoggerFactory.getLogger(SecureRemoteInvocationFactory.class);

    public static final String SESSION_ID_KEY = Session.class.getName() + "_ID_KEY";
    public static final String INET_ADDRESS_KEY = InetAddress.class.getName() + "_KEY";

    private static final String SESSION_ID_SYSTEM_PROPERTY_NAME = "ki.session.id";

    /**
     * Creates a {@link RemoteInvocation} with the current session ID as an
     * {@link RemoteInvocation#getAttribute(String) attribute}.
     *
     * @param mi the method invocation that the remote invocation should be based on.
     * @return a remote invocation object containing the current session ID as an attribute.
     */
    public RemoteInvocation createRemoteInvocation(MethodInvocation mi) {

        Serializable sessionId = null;
        InetAddress inet = null;
        boolean sessionManagerMethodInvocation = false;

        //If the calling MI is for a remoting SessionManager proxy, we need to acquire the session ID from the method
        //argument and NOT interact with SecurityUtils/subject.getSession to avoid a stack overflow
        if (SessionManager.class.equals(mi.getMethod().getDeclaringClass())) {
            sessionManagerMethodInvocation = true;
            //for SessionManager calls, all method calls require the session id as the first argument, with
            //the exception of 'start' that takes in an InetAddress.  So, ignore that one case:
            Object firstArg = mi.getArguments()[0];
            if (!(firstArg instanceof InetAddress)) {
                sessionId = (Serializable) firstArg;
            }
        }

        //tried the proxy.  If sessionId is still null, only then try the Subject:
        if (sessionId == null && !sessionManagerMethodInvocation) {
            Subject subject = SecurityUtils.getSubject();
            Session session = subject.getSession(false);
            if (session != null) {
                inet = session.getHostAddress();                
                sessionId = session.getId();
            }
        }

        //No call to the sessionManager, and the Subject doesn't have a session.  Try a system property
        //as a last result:
        if (sessionId == null) {
            if (log.isTraceEnabled()) {
                log.trace("No Session found for the currently executing subject via subject.getSession(false).  " +
                    "Attempting to revert back to the 'ki.session.id' system property...");
            }
            sessionId = System.getProperty(SESSION_ID_SYSTEM_PROPERTY_NAME);
            if (sessionId == null && log.isTraceEnabled()) {
                log.trace("No 'ki.session.id' system property found.  Heuristics have been exhausted; " +
                    "RemoteInvocation will not contain a sessionId.");
            }
        }

        if ( inet == null ) {
            //try thread context:
            inet = ThreadContext.getInetAddress();
        }

        RemoteInvocation ri = new RemoteInvocation(mi);
        if (sessionId != null) {
            ri.addAttribute(SESSION_ID_KEY, sessionId);
        }
        if ( inet != null ) {
            ri.addAttribute(INET_ADDRESS_KEY, inet);
        }

        return ri;
    }
}
