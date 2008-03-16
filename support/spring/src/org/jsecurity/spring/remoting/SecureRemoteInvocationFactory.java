/*
 * Copyright 2005-2008 Jeremy Haile, Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */package org.jsecurity.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.session.Session;
import org.springframework.remoting.support.DefaultRemoteInvocationFactory;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;

/**
 * A {@link RemoteInvocationFactory} that passes the session ID to the server via a
 * {@link RemoteInvocation} {@link RemoteInvocation#getAttribute(String) attribute}.
 * This factory is the client-side part of
 * the JSecurity Spring remoting invocation.  A {@link SecureRemoteInvocationExecutor} should
 * be used to export the server-side remote services to ensure that the appropriate
 * Subject and Session are bound to the remote thread during execution.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class SecureRemoteInvocationFactory extends DefaultRemoteInvocationFactory {

    public static final String SESSION_ID_KEY = Session.class.getName() + "_ID_KEY";

    private static final String SESSION_ID_SYSTEM_PROPERTY_NAME = "jsecurity.session.id";

    /**
     * Creates a {@link RemoteInvocation} with the current session ID as an
     * {@link RemoteInvocation#getAttribute(String) attribute}.
     * @param methodInvocation the method invocation that the remote invocation should
     * be based on.
     * @return a remote invocation object containing the current session ID as an attribute.
     */
    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        String sessionId = System.getProperty(SESSION_ID_SYSTEM_PROPERTY_NAME);
        if( sessionId == null ) {
            throw new IllegalStateException( "System property [" + SESSION_ID_SYSTEM_PROPERTY_NAME + "] is not set.  " +
                    "This property must be set to the JSecurity session ID for remote calls to function." );
        }
        RemoteInvocation ri = new RemoteInvocation(methodInvocation);
        ri.addAttribute( SESSION_ID_KEY, sessionId );

        return ri;
    }
}
