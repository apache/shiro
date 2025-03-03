/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.servlet;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.session.HttpServletSession;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Wrapper class that uses a Shiro {@link Session Session} under the hood for all session operations instead of the
 * Servlet Container's session mechanism.  This is required in heterogeneous client environments where the Session
 * is used on both the business tier as well as in multiple client technologies (web, swing, flash, etc.) since
 * Servlet container sessions alone cannot support this feature.
 *
 * @since 0.2
 */
@SuppressWarnings("checkstyle:MagicNumber")
public class ShiroHttpSession implements HttpSession {

    /**
     * default session id name.
     */
    public static final String DEFAULT_SESSION_ID_NAME = "JSESSIONID";

    protected ServletContext servletContext;
    protected HttpServletRequest currentRequest;
    //'real' Shiro Session
    protected Session session;

    public ShiroHttpSession(Session session, HttpServletRequest currentRequest, ServletContext servletContext) {
        if (session instanceof HttpServletSession) {
            String msg = "Session constructor argument cannot be an instance of HttpServletSession.  This is enforced to "
                    + "prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException(msg);
        }
        this.session = session;
        this.currentRequest = currentRequest;
        this.servletContext = servletContext;
    }

    public Session getSession() {
        return this.session;
    }

    public long getCreationTime() {
        try {
            return getSession().getStartTimestamp().getTime();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String getId() {
        return getSession().getId().toString();
    }

    public long getLastAccessedTime() {
        return getSession().getLastAccessTime().getTime();
    }

    public ServletContext getServletContext() {
        return this.servletContext;
    }

    public void setMaxInactiveInterval(int i) {
        try {
            getSession().setTimeout(i * 1000L);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public int getMaxInactiveInterval() {
        try {
            return (Long.valueOf(getSession().getTimeout() / 1000)).intValue();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public Object getAttribute(String s) {
        try {
            return getSession().getAttribute(s);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    @Deprecated
    public Object getValue(String s) {
        return getAttribute(s);
    }

    protected Set<String> getKeyNames() {
        Collection<Object> keySet;
        try {
            keySet = getSession().getAttributeKeys();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
        Set<String> keyNames;
        if (keySet != null && !keySet.isEmpty()) {
            keyNames = new HashSet<String>(keySet.size());
            for (Object o : keySet) {
                keyNames.add(o.toString());
            }
        } else {
            keyNames = Set.of();
        }
        return keyNames;
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        Set<String> keyNames = getKeyNames();
        final Iterator<String> iterator = keyNames.iterator();
        return new Enumeration<>() {
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            public String nextElement() {
                return iterator.next();
            }
        };
    }

    @Deprecated
    public String[] getValueNames() {
        Set<String> keyNames = getKeyNames();
        String[] array = new String[keyNames.size()];
        if (keyNames.size() > 0) {
            array = keyNames.toArray(array);
        }
        return array;
    }

    protected void afterBound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener listener) {
            HttpSessionBindingEvent event = new HttpSessionBindingEvent(this, s, o);
            listener.valueBound(event);
        }
    }

    protected void afterUnbound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener listener) {
            HttpSessionBindingEvent event = new HttpSessionBindingEvent(this, s, o);
            listener.valueUnbound(event);
        }
    }

    public void setAttribute(String s, Object o) {
        try {
            getSession().setAttribute(s, o);
            afterBound(s, o);
        } catch (InvalidSessionException e) {
            //noinspection finally
            try {
                afterUnbound(s, o);
            } finally {
                //noinspection ThrowFromFinallyBlock
                throw new IllegalStateException(e);
            }
        }
    }

    @Deprecated
    public void putValue(String s, Object o) {
        setAttribute(s, o);
    }

    public void removeAttribute(String s) {
        try {
            Object attribute = getSession().removeAttribute(s);
            afterUnbound(s, attribute);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    @Deprecated
    public void removeValue(String s) {
        removeAttribute(s);
    }

    public void invalidate() {
        try {
            getSession().stop();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean isNew() {
        Boolean value = (Boolean) currentRequest.getAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW);
        return value != null && value.equals(Boolean.TRUE);
    }
}
