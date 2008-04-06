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
 * @see #getSecurityManager
 * @see #createSecurityManager
 * @author Les Hazlewood
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

        String mode = getSessionMode();
        if ( mode != null ) {
            defaultSecMgr.setSessionMode( mode );
        }

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
        SecurityManager securityManager = getSecurityManager();
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
