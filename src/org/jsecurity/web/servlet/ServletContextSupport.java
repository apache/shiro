package org.jsecurity.web.servlet;

import javax.servlet.ServletContext;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since Dec 7, 2007
 */
public class ServletContextSupport {

    public static final String SESSION_MODE_CONTEXT_PARAM_NAME = "sessionMode";
    public static final String WEB_SESSION_MODE = "web";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    private ServletContext servletContext = null;
    private String sessionMode = null;

    public ServletContext getServletContext() {
        return servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    protected String getStringInitParam( String paramName ) {
        return getServletContext().getInitParameter( paramName );
    }

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String sessionMode) {
        this.sessionMode = sessionMode;
    }

    protected void applySessionMode() {
        String mode = getStringInitParam(SESSION_MODE_CONTEXT_PARAM_NAME);
        if ( mode != null ) {
            mode = mode.trim();
            if ( mode.equalsIgnoreCase(WEB_SESSION_MODE) ) {
                setSessionMode( mode );
            } else if ( mode.equalsIgnoreCase(JSECURITY_SESSION_MODE) ) {
                setSessionMode( mode );
            } else {
                String msg = "Unknown '" + SESSION_MODE_CONTEXT_PARAM_NAME + "' context-param value.  " +
                    "The only recognized values are '" +
                    WEB_SESSION_MODE + "' and '" + JSECURITY_SESSION_MODE +
                    "'.  Please check your configuration and/or spelling.";
                throw new IllegalArgumentException( msg );
            }
        }
    }

    protected boolean isWebSessions() {
        return getSessionMode().equals( WEB_SESSION_MODE );
    }
}
