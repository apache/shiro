package org.jsecurity.web.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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

    protected transient final Log log = LogFactory.getLog( getClass() );

    private ServletContext servletContext = null;
    private String sessionMode = WEB_SESSION_MODE; //default

    public ServletContext getServletContext() {
        return servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    protected String getStringInitParam(String paramName) {
        return getServletContext().getInitParameter(paramName);
    }

    private ServletContext getServletContextNullCheck() {
        ServletContext servletContext = getServletContext();
        if (servletContext == null) {
            String msg = "ServletContext property must be set via the setServletContext method.";
            throw new IllegalStateException(msg);
        }
        return servletContext;
    }

    protected void setAttribute( String key, Object value ) {
        getServletContextNullCheck().setAttribute( key, value );
    }

    protected Object getAttribute( String key ) {
        return getServletContextNullCheck().getAttribute( key );
    }

    protected void removeAttribute( String key ) {
        getServletContextNullCheck().removeAttribute( key );
    }

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String mode) {
        if (mode != null) {
            mode = mode.trim();
            if (!mode.equalsIgnoreCase(WEB_SESSION_MODE) &&
                !mode.equalsIgnoreCase(JSECURITY_SESSION_MODE)) {
                String msg = "Unknown '" + SESSION_MODE_CONTEXT_PARAM_NAME + "' context-param value [" +
                    mode + "].  Recognized values are '" +
                    WEB_SESSION_MODE + "' and '" + JSECURITY_SESSION_MODE +
                    "' (without quotes).  Please check your configuration and/or spelling.";
                throw new IllegalArgumentException(msg);
            }
            this.sessionMode = mode;
        }
    }

    protected void applySessionMode() {
        setSessionMode( getStringInitParam(SESSION_MODE_CONTEXT_PARAM_NAME) );
    }

    protected boolean isWebSessions() {
        return getSessionMode().equals(WEB_SESSION_MODE);
    }
}
