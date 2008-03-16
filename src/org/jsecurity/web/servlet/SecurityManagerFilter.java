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
package org.jsecurity.web.servlet;

import org.jsecurity.mgt.SecurityManager;

import javax.servlet.ServletContext;

/**
 * ServletFilter that accesses the application's web-accessible SecurityManager instance.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class SecurityManagerFilter extends OncePerRequestFilter {

    protected SecurityManagerListener securityManagerListener = null;

    public SecurityManagerFilter(){}

    protected void onFilterConfigSet() throws Exception {
        applySessionMode();
        org.jsecurity.mgt.SecurityManager securityManager = getSecurityManager();
        //not using the loader explicitly or not overridden, so lets start one:
        if ( securityManager == null ) {
            securityManagerListener = new SecurityManagerListener();
            securityManagerListener.setServletContext( getServletContext() );
            securityManagerListener.setSessionMode( getSessionMode() );
            securityManagerListener.init();
        }
        afterSecurityManagerSet();
    }

    /**
     * Template initialization hook for subclasses to continue init logic after the SecurityManager is available.
     *
     * <p>The SecurityManager instance will be available when this is called via the
     * {@link #getSecurityManager() getSecurityManager} method.
     * @throws Exception if the subclass has a problem initializing.
     */
    protected void afterSecurityManagerSet() throws Exception {
    }

    public void destroy() {
        if ( securityManagerListener != null ) {
            securityManagerListener.destroy();
        }
    }

    protected SecurityManager getSecurityManager() {
        ServletContext servletContext = getServletContext();
        return (SecurityManager)servletContext.getAttribute( SecurityManagerListener.SECURITY_MANAGER_CONTEXT_KEY);
    }

}
