package org.jsecurity.web.servlet;

import org.jsecurity.SecurityManager;

import javax.servlet.ServletContext;

/**
 * ServletFilter that accesses the application's web-accessible SecurityManager instance.
 *
 * @author Les Hazlewood
 * @since Feb 4, 2008 7:25:28 PM
 */
public abstract class SecurityManagerFilter extends OncePerRequestFilter {

    SecurityManagerListener securityManagerListener = null;

    protected void onFilterConfigSet() throws Exception {
        applySessionMode();
        SecurityManager securityManager = getSecurityManager();
        //not using the loader explicitly or not overridden, so lets start one:
        if ( securityManager == null ) {
            securityManagerListener = new SecurityManagerListener();
            securityManagerListener.setServletContext( getServletContext() );
            securityManagerListener.init();
        }
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
