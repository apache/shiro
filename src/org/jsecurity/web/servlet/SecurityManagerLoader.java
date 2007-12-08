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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.DefaultSecurityManager;
import org.jsecurity.SecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.Destroyable;

import javax.servlet.ServletContext;
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
 * return that instance by overriding the {@link #getSecurityManager() getSecurityManager()} method.</P>
 *
 * <p>If there is no business-tier, i.e. this is a 'pure' web application, then a <tt>SecurityManager</tt> instance
 * needs to be created (instantiated) explicitly.  This implementation will do that automatically by default, but if
 * you wish to change the default logic, you'll need to override the
 * {@link #createSecurityManager() createSecurityManager()} method.  Subclasses with a proper business tier as
 * described above do not need to worry about doing this.
 *
 * @see #getSecurityManager
 * @see #createSecurityManager
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SecurityManagerLoader extends ServletContextSupport {

    public static final String SECURITY_MANAGER_CONTEXT_KEY = SecurityManagerLoader.class.getName() + "_SECURITY_MANAGER";

    protected final transient Log log = LogFactory.getLog( getClass() );

    private SecurityManager securityManager = null;
    private boolean securityManagerImplicitlyCreated = false;

    public void init() {
        if ( getServletContext() == null ) {
            throw new IllegalStateException( "servletContext property must be set." );
        }
        applySessionMode();
        ensureSecurityManager();
    }

    public void ensureSecurityManager() {
        SecurityManager securityManager = getSecurityManager();
        if ( securityManager == null ) {
            this.securityManager = createSecurityManager();
            this.securityManagerImplicitlyCreated = true;
        }
        bindToServletContext( securityManager );
    }

    protected void bindToServletContext( SecurityManager securityManager ) {
        if ( securityManager == null ) {
            throw new IllegalArgumentException( "securityManager argument cannot be null." );
        }
        ServletContext servletContext = getServletContext();
        if ( servletContext == null ) {
            String msg = "ServletContext property must be set via the setServletContext method.";
            throw new IllegalStateException( msg );
        }
        if ( servletContext.getAttribute( SECURITY_MANAGER_CONTEXT_KEY ) != null ) {
            String msg = "SecurityManager already bound to ServletContext.  Please check your configuration to ensure " +
                "you don't have mutliple SecurityManager Loaders configured (listener, servlet, etc).";
            throw new IllegalStateException( msg );
        }
        servletContext.setAttribute( SECURITY_MANAGER_CONTEXT_KEY, securityManager );
    }

    protected SecurityManager createSecurityManager() {
        DefaultSecurityManager defaultSecMgr = new DefaultSecurityManager();
        this.securityManagerImplicitlyCreated = true;

        if ( !getSessionMode().equals(WEB_SESSION_MODE) ) {
            // not using web-only sessions - need JSecurity's more robust Session support,
            // so make sure the SessionManagement infrastructure is eagerly initialized w/ the 
            // SecurityManager to catch errors early:
            defaultSecMgr.setLazySessions( false );
        }

        List<Realm> realms = getRealms();

        if ( realms != null && !realms.isEmpty() ) {
            defaultSecMgr.setRealms( realms );
        } else {
            Realm realm = getRealm();
            if ( realm != null ) {
                defaultSecMgr.setRealm( realm );
            }
        }

        defaultSecMgr.init();

        return defaultSecMgr;
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

    protected void destroySecurityManager() {
        ServletContext servletContext = getServletContext();
        
        if ( this.securityManagerImplicitlyCreated && this.securityManager != null )  {
            if ( this.securityManager instanceof Destroyable ) {
                try {
                    ((Destroyable)this.securityManager).destroy();
                } catch ( Exception e ) {
                    if ( log.isWarnEnabled() ) {
                        log.warn( "Unable to cleanly destroy implicitly created SecurityManager instance.  " +
                            "Ignoring and continuing shut-down.", e );
                    }
                }
            }
        }
        servletContext.removeAttribute( SECURITY_MANAGER_CONTEXT_KEY );
    }
}
