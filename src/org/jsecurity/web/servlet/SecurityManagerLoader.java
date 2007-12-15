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

import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.SecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.session.SessionFactoryAware;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.web.support.DefaultWebSessionFactory;
import org.jsecurity.web.support.HttpContainerWebSessionFactory;

import java.util.List;

/**
 * Utility superclass for a web application that consolidates SecurityManager acquisition and/or creation logic during
 * application startup.  Subclasses are expected to utilize startup mechanisms/APIs supported by the Servlet Container
 * (for example, <tt>ServletContextListener</tt>, <tt>Servlet</tt>, etc), and call the methods in this class to
 * reduce the amount of code required.
 *
 * <p><b>Clean Architecture Note:</b> A JSecurity <tt>SecurityManager</tt> is really considered a business-tier
 * component and should be created in the application's business-tier configuration (e.g. Spring, Pico, Guice, JBoss,
 * etc) if such a configuration exists.  If this business-tier does exist, subclasses of this one should acquire and
 * return that instance by overriding the {@link #getSecurityManager() getSecurityManager()} method.</p>
 *
 * <p>If there is no business-tier, i.e. this is a 'pure' web application, then a <tt>SecurityManager</tt> instance
 * needs to be created (instantiated) explicitly.  This implementation will do that automatically by default, but if
 * you wish to change the default logic, you'll need to override the
 * {@link #createSecurityManager() createSecurityManager()} method.  Subclasses with a proper business tier as
 * described above do not need to worry about doing this.
 *
 * @author Les Hazlewood
 * @see #getSecurityManager
 * @see #createSecurityManager
 * @since 0.2
 */
public class SecurityManagerLoader extends ServletContextSupport {

    public static final String SECURITY_MANAGER_CONTEXT_KEY = SecurityManagerLoader.class.getName() + "_SECURITY_MANAGER";
    public static final String WEB_SESSION_FACTORY_CONTEXT_KEY = WebSessionFactory.class.getName() + "_WEB_SESSION_FACTORY";

    private WebSessionFactory webSessionFactory = null;
    private boolean webSessionFactoryImplicitlyCreated = false;
    private SecurityManager securityManager = null;
    private boolean securityManagerImplicitlyCreated = false;

    public void init() {
        if (getServletContext() == null) {
            throw new IllegalStateException("servletContext property must be set.");
        }
        applySessionMode();
        ensureSecurityManager();
    }

    public WebSessionFactory getWebSessionFactory() {
        return this.webSessionFactory;
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

    protected void assertSessionFactoryAware(SecurityManager securityManager) {
        if (!(securityManager instanceof SessionFactoryAware)) {
            String msg = "The " + getClass().getName() + " class requires that the SecurityManager instance must " +
                "implement the " + SessionFactoryAware.class.getName() + " interface.";
            throw new IllegalStateException(msg);
        }
    }

    protected void bind( String name, String key, Object value ) {
        if ( value == null ) {
            throw new IllegalArgumentException( name + " argument cannot be null." );
        }
        if ( getAttribute( key ) != null ) {
            String msg = name + " already bound to ServletContext.  Please check your configuration to ensure " +
                "you don't have mutliple SecurityManager Loaders configured (listener, servlet, etc).";
            throw new IllegalStateException(msg);    
        }
        setAttribute( key, value );
    }

    protected void bind( WebSessionFactory webSessionFactory ) {
        bind( "webSessionFactory", WEB_SESSION_FACTORY_CONTEXT_KEY, webSessionFactory );
    }

    protected void bind( SecurityManager securityManager ) {
        bind( "securityManager", SECURITY_MANAGER_CONTEXT_KEY, securityManager );
    }

    private WebSessionFactory createWebSessionFactory() {
        if ( isWebSessions() ) {
            return new HttpContainerWebSessionFactory();
        } else {
            return new DefaultWebSessionFactory();
        }
    }

    protected SecurityManager createSecurityManager() {
        WebSessionFactory webSessionFactory = getWebSessionFactory();
        if ( !(webSessionFactory instanceof SessionFactory ) ) {
            String msg = "If you do not configure a SecurityManager, the " + getClass().getName() + " implementation " +
                "expects the WebSessionFactory instance to also implement the " +
                SessionFactory.class.getName() + " interface as well.";
            throw new IllegalStateException( msg );
        }
        DefaultSecurityManager defaultSecMgr = new DefaultSecurityManager();
        defaultSecMgr.setSessionFactory( (SessionFactory)webSessionFactory );

        if ( !isWebSessions() ) {
            // not using web-only sessions - need JSecurity's more robust Session support,
            // so make sure the SessionManagement infrastructure is eagerly initialized w/ the
            // SecurityManager to catch errors early:
            defaultSecMgr.setLazySessions(false);
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

    public void ensureWebSessionFactory() {
        WebSessionFactory webSessionFactory = getWebSessionFactory();

        if (webSessionFactory == null) {
            SecurityManager securityManager = getSecurityManager();
            if (securityManager != null) {
                assertSessionFactoryAware(securityManager);
                SessionFactory sf = ((SessionFactoryAware) securityManager).getSessionFactory();
                if (!(sf instanceof WebSessionFactory)) {
                    String msg = "The " + getClass().getName() + " requires that the configured " +
                        "SecurityManager's getSessionFactory() method return an instance of " +
                        WebSessionFactory.class.getName() + " in addition to the regular SessionFactory interface";
                    throw new IllegalStateException(msg);
                }
                this.webSessionFactory = (WebSessionFactory) sf;
            } else {
                //create a web session factory from scratch and make it available for injection into the
                //the SecurityManager that will be created after this method call.
                webSessionFactory = createWebSessionFactory();
                if (webSessionFactory == null) {
                    String msg = "webSessionFactory instance returned from createWebSessionFactory() call cannot " +
                        "be null.";
                    throw new IllegalStateException(msg);
                }
                if (!(webSessionFactory instanceof SessionFactory)) {
                    String msg = "The " + getClass().getName() + " implementation requires the WebSessionFactory " +
                        "instance returned from createWebSessionFactory() to implement the " +
                        SessionFactory.class.getName() + " interface if you do not configure a SecurityManager";
                    throw new IllegalStateException(msg);
                }
                if ( webSessionFactory instanceof Initializable ) {
                    try {
                        ((Initializable)webSessionFactory).init();
                    } catch (Exception e) {
                        String msg = "Unable to cleanly initialize the implicitly created WebSessionFactory " +
                            "instance.  Please verify your implementation's init() method.";
                        throw new IllegalStateException( msg, e );
                    }
                }

                this.webSessionFactory = webSessionFactory;
                this.webSessionFactoryImplicitlyCreated = true;
            }
        }

        bind(webSessionFactory);
    }

    public void ensureSecurityManager() {
        ensureWebSessionFactory();
        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            securityManager = createSecurityManager();
            if (securityManager == null) {
                String msg = "securityManager instance returned from createSecurityManager() call cannot " +
                    "be null.";
                throw new IllegalStateException(msg);
            }
            this.securityManager = securityManager;
            this.securityManagerImplicitlyCreated = true;
        }

        bind(securityManager);
    }

    protected void destroyWebSessionFactory() {
        if (this.webSessionFactoryImplicitlyCreated && this.webSessionFactory != null) {
            if (this.webSessionFactory instanceof Destroyable) {
                try {
                    ((Destroyable) this.webSessionFactory).destroy();
                } catch (Exception e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to cleanly destroy implicitly created WebSessionFactory instance.  " +
                            "Ignoring and continuing shut-down.", e);
                    }
                }
            }
        }
        removeAttribute(WEB_SESSION_FACTORY_CONTEXT_KEY);
    }

    protected void destroySecurityManager() {
        if (this.securityManagerImplicitlyCreated && this.securityManager != null) {
            if (this.securityManager instanceof Destroyable) {
                try {
                    ((Destroyable) this.securityManager).destroy();
                } catch (Exception e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to cleanly destroy implicitly created SecurityManager instance.  " +
                            "Ignoring and continuing shut-down.", e);
                    }
                }
            }
        }
        removeAttribute(SECURITY_MANAGER_CONTEXT_KEY);
    }

    public void destroy() {
        destroySecurityManager();
        destroyWebSessionFactory();
    }

}
