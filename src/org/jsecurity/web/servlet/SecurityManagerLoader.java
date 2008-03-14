/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
import org.jsecurity.realm.Realm;
import org.jsecurity.util.LifecycleUtils;
import org.jsecurity.web.WebSecurityManager;

import java.util.List;

/**
 * Utility superclass for a web application that consolidates SecurityManager acquisition and/or creation logic during
 * application startup.  Subclasses are expected to utilize startup mechanisms/APIs supported by the Servlet Container
 * (for example, <tt>ServletContextListener</tt>, <tt>Servlet</tt>, etc), and call the methods in this class to
 * reduce the amount of code required.
 * <p/>
 * <p><b>Clean Architecture Note:</b> A JSecurity <tt>SecurityManager</tt> is really considered a business-tier
 * component and should be created in the application's business-tier configuration (e.g. Spring, Pico, Guice, JBoss,
 * etc) if such a configuration exists.  If this business-tier does exist, subclasses of this one should acquire and
 * return that instance by overriding the {@link #getSecurityManager() getSecurityManager()} method.</p>
 * <p/>
 * <p>If there is no business-tier, i.e. this is a 'pure' web application, then a <tt>SecurityManager</tt> instance
 * needs to be created (instantiated) explicitly.  This implementation will do this automatically by default, but if
 * you wish to change the default logic, you'll need to override the
 * {@link #createSecurityManager() createSecurityManager()} method.
 *
 * @author Les Hazlewood
 * @see #getSecurityManager
 * @see #createSecurityManager
 * @since 0.2
 */
public class SecurityManagerLoader extends ServletContextSupport {

    public static final String SECURITY_MANAGER_CONTEXT_KEY = SecurityManagerLoader.class.getName() + "_SECURITY_MANAGER";

    private SecurityManager securityManager = null;

    public void init() {
        if (getServletContext() == null) {
            throw new IllegalStateException("servletContext property must be set.");
        }
        applySessionMode();
        ensureSecurityManager();
    }

    public SecurityManager getSecurityManager() {
        return this.securityManager;
    }

    protected List<Realm> getRealms() {
        return null;
    }

    protected Realm getRealm() {
        return null;
    }

    protected void bind(SecurityManager securityManager) {
        bind("securityManager", SECURITY_MANAGER_CONTEXT_KEY, securityManager);
    }

    protected SecurityManager createSecurityManager() {
        WebSecurityManager defaultSecMgr = new WebSecurityManager();

        defaultSecMgr.setSessionMode( getSessionMode() );

        List<Realm> realms = getRealms();

        if (realms != null && !realms.isEmpty()) {
            defaultSecMgr.setRealms(realms);
        } else {
            Realm realm = getRealm();
            if (realm != null) {
                defaultSecMgr.setRealm(realm);
            }
        }

        defaultSecMgr.init();

        return defaultSecMgr;
    }

    public void ensureSecurityManager() {
        org.jsecurity.mgt.SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            securityManager = createSecurityManager();
            if (securityManager == null) {
                String msg = "securityManager instance returned from createSecurityManager() call cannot " +
                        "be null.";
                throw new IllegalStateException(msg);
            }
            this.securityManager = securityManager;
        }

        bind(securityManager);
    }

    public void destroy() {
        removeAttribute( SECURITY_MANAGER_CONTEXT_KEY );
        LifecycleUtils.destroy( this.securityManager );
        this.securityManager = null;
    }

}
