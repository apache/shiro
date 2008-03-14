/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
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
