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
package org.apache.shiro.web.session;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.servlet.ShiroHttpSession;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

/**
 * {@link Session Session} implementation that is backed entirely by a standard servlet container
 * {@link HttpSession HttpSession} instance.  It does not interact with any of Shiro's session-related components
 * {@code SessionManager}, {@code SecurityManager}, etc, and instead satisfies all method implementations by interacting
 * with a servlet container provided {@link HttpSession HttpSession} instance.
 *
 * @since 1.0
 */
public class HttpServletSession implements Session {

    private static final String HOST_SESSION_KEY = HttpServletSession.class.getName() + ".HOST_SESSION_KEY";
    private static final String TOUCH_OBJECT_SESSION_KEY = HttpServletSession.class.getName() + ".TOUCH_OBJECT_SESSION_KEY";

    private HttpSession httpSession = null;

    public HttpServletSession(HttpSession httpSession, String host) {
        if (httpSession == null) {
            String msg = "HttpSession constructor argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (httpSession instanceof ShiroHttpSession) {
            String msg = "HttpSession constructor argument cannot be an instance of ShiroHttpSession.  This " +
                    "is enforced to prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException(msg);
        }
        this.httpSession = httpSession;
        if (StringUtils.hasText(host)) {
            setHost(host);
        }
    }

    public Serializable getId() {
        return httpSession.getId();
    }

    public Date getStartTimestamp() {
        return new Date(httpSession.getCreationTime());
    }

    public Date getLastAccessTime() {
        return new Date(httpSession.getLastAccessedTime());
    }

    public long getTimeout() throws InvalidSessionException {
        try {
            return httpSession.getMaxInactiveInterval() * 1000L;
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        try {
            int timeout = (int) (maxIdleTimeInMillis / 1000);
            httpSession.setMaxInactiveInterval(timeout);
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    protected void setHost(String host) {
        setAttribute(HOST_SESSION_KEY, host);
    }

    public String getHost() {
        return (String) getAttribute(HOST_SESSION_KEY);
    }

    public void touch() throws InvalidSessionException {
        //just manipulate the session to update the access time:
        try {
            httpSession.setAttribute(TOUCH_OBJECT_SESSION_KEY, TOUCH_OBJECT_SESSION_KEY);
            httpSession.removeAttribute(TOUCH_OBJECT_SESSION_KEY);
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public void stop() throws InvalidSessionException {
        try {
            httpSession.invalidate();
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        try {
            Enumeration namesEnum = httpSession.getAttributeNames();
            Collection<Object> keys = null;
            if (namesEnum != null) {
                keys = new ArrayList<Object>();
                while (namesEnum.hasMoreElements()) {
                    keys.add(namesEnum.nextElement());
                }
            }
            return keys;
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    private static String assertString(Object key) {
        if (!(key instanceof String)) {
            String msg = "HttpSession based implementations of the Shiro Session interface requires attribute keys " +
                    "to be String objects.  The HttpSession class does not support anything other than String keys.";
            throw new IllegalArgumentException(msg);
        }
        return (String) key;
    }

    public Object getAttribute(Object key) throws InvalidSessionException {
        try {
            return httpSession.getAttribute(assertString(key));
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        try {
            httpSession.setAttribute(assertString(key), value);
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public Object removeAttribute(Object key) throws InvalidSessionException {
        try {
            String sKey = assertString(key);
            Object removed = httpSession.getAttribute(sKey);
            httpSession.removeAttribute(sKey);
            return removed;
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }
}
