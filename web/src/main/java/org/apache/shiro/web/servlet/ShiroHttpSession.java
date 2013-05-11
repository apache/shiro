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

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;
import java.util.*;


/**
 * Wrapper class that uses a Shiro {@link Session Session} under the hood for all session operations instead of the
 * Servlet Container's session mechanism.  This is required in heterogeneous client environments where the Session
 * is used on both the business tier as well as in multiple client technologies (web, swing, flash, etc) since
 * Servlet container sessions alone cannot support this feature.
 *
 * @since 0.2
 */
public class ShiroHttpSession implements HttpSession {

    //TODO - complete JavaDoc

    public static final String DEFAULT_SESSION_ID_NAME = "JSESSIONID";

    private static final Enumeration EMPTY_ENUMERATION = new Enumeration() {
        public boolean hasMoreElements() {
            return false;
        }

        public Object nextElement() {
            return null;
        }
    };

    @SuppressWarnings({"deprecation"})
    private static final javax.servlet.http.HttpSessionContext HTTP_SESSION_CONTEXT =
            new javax.servlet.http.HttpSessionContext() {
                public HttpSession getSession(String s) {
                    return null;
                }

                public Enumeration getIds() {
                    return EMPTY_ENUMERATION;
                }
            };

    protected ServletContext servletContext = null;
    protected HttpServletRequest currentRequest = null;
    protected Session session = null; //'real' Shiro Session

    public ShiroHttpSession(Session session, HttpServletRequest currentRequest, ServletContext servletContext) {
        if (session instanceof HttpServletSession) {
            String msg = "Session constructor argument cannot be an instance of HttpServletSession.  This is enforced to " +
                    "prevent circular dependencies and infinite loops.";
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
            getSession().setTimeout(i * 1000);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public int getMaxInactiveInterval() {
        try {
            return (new Long(getSession().getTimeout() / 1000)).intValue();
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings({"deprecation"})
    public javax.servlet.http.HttpSessionContext getSessionContext() {
        return HTTP_SESSION_CONTEXT;
    }

    public Object getAttribute(String s) {
        try {
            return getSession().getAttribute(s);
        } catch (InvalidSessionException e) {
            throw new IllegalStateException(e);
        }
    }

    public Object getValue(String s) {
        return getAttribute(s);
    }

    @SuppressWarnings({"unchecked"})
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
            keyNames = Collections.EMPTY_SET;
        }
        return keyNames;
    }

    public Enumeration getAttributeNames() {
        Set<String> keyNames = getKeyNames();
        final Iterator iterator = keyNames.iterator();
        return new Enumeration() {
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            public Object nextElement() {
                return iterator.next();
            }
        };
    }

    public String[] getValueNames() {
        Set<String> keyNames = getKeyNames();
        String[] array = new String[keyNames.size()];
        if (keyNames.size() > 0) {
            array = keyNames.toArray(array);
        }
        return array;
    }

    protected void afterBound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener) o;
            HttpSessionBindingEvent event = new HttpSessionBindingEvent(this, s, o);
            listener.valueBound(event);
        }
    }

    protected void afterUnbound(String s, Object o) {
        if (o instanceof HttpSessionBindingListener) {
            HttpSessionBindingListener listener = (HttpSessionBindingListener) o;
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
