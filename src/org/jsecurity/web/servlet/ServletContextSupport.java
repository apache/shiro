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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.web.DefaultWebSecurityManager;

import javax.servlet.ServletContext;

/**
 * TODO - class javadoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class ServletContextSupport {

    public static final String SESSION_MODE_CONTEXT_PARAM_NAME = "sessionMode";
    public static final String HTTP_SESSION_MODE = DefaultWebSecurityManager.HTTP_SESSION_MODE;
    public static final String JSECURITY_SESSION_MODE = DefaultWebSecurityManager.JSECURITY_SESSION_MODE;

    protected transient final Log log = LogFactory.getLog(getClass());

    private ServletContext servletContext = null;

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

    protected void setAttribute(String key, Object value) {
        getServletContextNullCheck().setAttribute(key, value);
    }

    protected Object getAttribute(String key) {
        return getServletContextNullCheck().getAttribute(key);
    }

    protected void removeAttribute(String key) {
        getServletContextNullCheck().removeAttribute(key);
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
}
