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

    protected SecurityManagerListener securityManagerListener = null;
    protected SecurityManager securityManager = null;

    protected void onFilterConfigSet() throws Exception {
        applySessionMode();
        SecurityManager securityManager = getSecurityManager();
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
