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
import java.lang.reflect.InvocationTargetException;

import org.springframework.remoting.support.DefaultRemoteInvocationExecutor;
import org.springframework.remoting.support.RemoteInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ki.mgt.SecurityManager;
import org.apache.ki.util.ThreadContext;


/**
 * An implementation of the Spring {@link org.springframework.remoting.support.RemoteInvocationExecutor}
 * that binds a {@code sessionId} to the incoming thread to make it available to the {@code SecurityManager}
 * implementation during the thread execution.  The {@code SecurityManager} implementation can use this sessionId
 * to reconstitute the {@code Subject} instance based on persistent state in the corresponding {@code Session}.
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

    public void setSecurityManager(org.apache.ki.mgt.SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    @SuppressWarnings({"unchecked"})
    public Object invoke(RemoteInvocation invocation, Object targetObject) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        try {
            Serializable sessionId = invocation.getAttribute(SecureRemoteInvocationFactory.SESSION_ID_KEY);
            if (sessionId != null) {
                ThreadContext.bindSessionId(sessionId);
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("RemoteInvocation did not contain a JSecurity Session id attribute under " +
                            "key [" + SecureRemoteInvocationFactory.SESSION_ID_KEY + "].  A Subject based " +
                            "on an existing Session will not be available during the method invocatin.");
                }
            }
            ThreadContext.bind(securityManager);
            ThreadContext.bind(securityManager.getSubject());

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
