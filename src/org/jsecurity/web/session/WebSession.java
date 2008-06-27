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
package org.jsecurity.web.session;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.web.servlet.JSecurityHttpSession;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class WebSession implements Session {

    private static final String INET_ADDRESS_SESSION_KEY = WebSession.class.getName() + "_INET_ADDRESS_SESSION_KEY";
    private static final String TOUCH_OBJECT_SESSION_KEY = WebSession.class.getName() + "_TOUCH_OBJECT_SESSION_KEY";

    private HttpSession httpSession = null;

    public WebSession(HttpSession httpSession, InetAddress inetAddress) {
        if (httpSession == null) {
            String msg = "HttpSession constructor argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        if (httpSession instanceof JSecurityHttpSession) {
            String msg = "HttpSession constructor argument cannot be an instance of JSecurityHttpSession.  This " +
                    "is enforced to prevent circular dependencies and infinite loops.";
            throw new IllegalArgumentException(msg);
        }
        this.httpSession = httpSession;
        if (inetAddress != null) {
            setHostAddress(inetAddress);
        }
    }

    public Serializable getId() {
        return httpSession.getId();
    }

    public Date getStartTimestamp() {
        return new Date(httpSession.getCreationTime());
    }

    public Date getStopTimestamp() {
        return null;
    }

    public Date getLastAccessTime() {
        return new Date(httpSession.getLastAccessedTime());
    }

    public boolean isExpired() {
        return false;
    }

    public long getTimeout() throws InvalidSessionException {
        try {
            return httpSession.getMaxInactiveInterval() * 1000;
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        try {
            int timeout = Long.valueOf(maxIdleTimeInMillis / 1000).intValue();
            httpSession.setMaxInactiveInterval(timeout);
        } catch (Exception e) {
            throw new InvalidSessionException(e);
        }
    }

    protected void setHostAddress(InetAddress hostAddress) {
        setAttribute(INET_ADDRESS_SESSION_KEY, hostAddress);
    }

    public InetAddress getHostAddress() {
        return (InetAddress) getAttribute(INET_ADDRESS_SESSION_KEY);
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
            String msg = "HttpSession based implementations of the JSecurity Session interface requires attribute keys " +
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
