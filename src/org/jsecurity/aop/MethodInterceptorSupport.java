/*
 * Copyright 2005-2008 Les Hazlewood
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
 */
package org.jsecurity.aop;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityUtils;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.subject.Subject;

/**
 * This class is an abstraction of AOP method interceptor behavior specific to JSecurity that
 * leaves AOP implementation specifics to be handled by subclass implementations.  This implementation primarily
 * enables a <tt>Log</tt> and makes available the application's {@link org.jsecurity.mgt.SecurityManager SecurityManager}
 * for use by subclasses, if one is provided (otherwise the subject will be retrieved using SecurityUtils).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class MethodInterceptorSupport implements MethodInterceptor {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected org.jsecurity.mgt.SecurityManager securityManager = null;

    public MethodInterceptorSupport(){}

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    protected Subject getSubject() {
        if( getSecurityManager() != null ) {
            return getSecurityManager().getSubject();
        } else {
            return SecurityUtils.getSubject();
        }
    }
}
