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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.web.WebSecurityManager;

import javax.servlet.ServletContext;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class ServletContextSupport {

    public static final String SESSION_MODE_CONTEXT_PARAM_NAME = "sessionMode";
    public static final String HTTP_SESSION_MODE = WebSecurityManager.HTTP_SESSION_MODE;
    public static final String JSECURITY_SESSION_MODE = WebSecurityManager.JSECURITY_SESSION_MODE;

    protected transient final Log log = LogFactory.getLog( getClass() );

    private ServletContext servletContext = null;
    private String sessionMode = HTTP_SESSION_MODE; //default

    public ServletContext getServletContext() {
        return servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    protected String getContextInitParam(String paramName) {
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

    protected void bind(String name, String key, Object value) {
        if (value == null) {
            throw new IllegalArgumentException(name + " argument cannot be null.");
        }
        if (getAttribute(key) != null) {
            String msg = name + " already bound to ServletContext.  Please check your configuration to ensure " +
                    "you don't have mutliple SecurityManager Loaders configured (listener, servlet, etc).";
            throw new IllegalStateException(msg);
        }
        setAttribute(key, value);
    }

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String mode) {
        if (mode != null) {
            mode = mode.trim();
            if (!mode.equalsIgnoreCase(HTTP_SESSION_MODE) &&
                !mode.equalsIgnoreCase(JSECURITY_SESSION_MODE)) {
                String msg = "Unknown '" + SESSION_MODE_CONTEXT_PARAM_NAME + "' context-param value [" +
                    mode + "].  Recognized values are '" +
                        HTTP_SESSION_MODE + "' and '" + JSECURITY_SESSION_MODE +
                    "' (without quotes).  Please check your configuration and/or spelling.";
                throw new IllegalArgumentException(msg);
            }
            this.sessionMode = mode;
        }
    }

    protected void applySessionMode() {
        setSessionMode( getContextInitParam(SESSION_MODE_CONTEXT_PARAM_NAME) );
    }

    protected boolean isHttpSessions() {
        return getSessionMode().equals(HTTP_SESSION_MODE);
    }
}
