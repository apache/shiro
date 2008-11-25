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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.session.Session;
import org.jsecurity.subject.DelegatingSubject;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.DefaultWebSecurityManager;
import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * An implementation of the Spring {@link org.springframework.remoting.support.RemoteInvocationExecutor}
 * that binds the correct {@link Session} and {@link org.jsecurity.subject.Subject} to the
 * remote invocation thread during a remote execution.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SecureRemoteInvocationExecutor extends DefaultRemoteInvocationExecutor {

    //TODO - complete JavaDoc

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private static final Log log = LogFactory.getLog(SecureRemoteInvocationExecutor.class);

    /**
     * The SecurityManager used to retrieve realms that should be associated with the
     * created <tt>Subject</tt>s upon remote invocation.
     */
    private SecurityManager securityManager;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setSecurityManager(org.jsecurity.mgt.SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    protected InetAddress getInetAddress(RemoteInvocation invocation, Object targetObject) {
        try {
            return InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    protected PrincipalCollection getPrincipals(RemoteInvocation invocation, Object targetObject, Session session) {
        return (PrincipalCollection) session.getAttribute(DefaultWebSecurityManager.PRINCIPALS_SESSION_KEY);
    }

    protected boolean isAuthenticated(RemoteInvocation invocation, Object targetObject, Session session, PrincipalCollection principals) {
        if (principals != null) {
            Boolean authc = (Boolean) session.getAttribute(DefaultWebSecurityManager.AUTHENTICATED_SESSION_KEY);
            return authc != null && authc;
        }
        return false;
    }

    @SuppressWarnings({"unchecked"})
    public Object invoke(RemoteInvocation invocation, Object targetObject) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        try {
            PrincipalCollection principals = null;
            boolean authenticated = false;
            InetAddress inetAddress = getInetAddress(invocation, targetObject);
            Session session = null;

            Serializable sessionId = invocation.getAttribute(SecureRemoteInvocationFactory.SESSION_ID_KEY);

            if (sessionId != null) {
                session = securityManager.getSession(sessionId);
                principals = getPrincipals(invocation, targetObject, session);
                authenticated = isAuthenticated(invocation, targetObject, session, principals);
            } else {
                if (log.isWarnEnabled()) {
                    log.warn("RemoteInvocation object did not contain a JSecurity Session id under " +
                            "attribute name [" + SecureRemoteInvocationFactory.SESSION_ID_KEY + "].  A Session will not " +
                            "be available to the method.  Ensure that clients are using a " +
                            "SecureRemoteInvocationFactory to prevent this problem.");
                }
            }

            Subject subject = new DelegatingSubject(principals, authenticated, inetAddress, session, securityManager);

            ThreadContext.bind(securityManager);
            ThreadContext.bind(subject);

            return super.invoke(invocation, targetObject);

        } catch (NoSuchMethodException nsme) {
            throw nsme;
        } catch (IllegalAccessException iae) {
            throw iae;
        } catch (InvocationTargetException ite) {
            throw ite;
        } catch (Throwable t) {
            throw new InvocationTargetException(t);
        } finally {
            ThreadContext.clear();
        }
    }
}
