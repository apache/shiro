/*
 * Copyright 2008 Les Hazlewood
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
package org.apache.shiro.session.mgt;

import java.io.Serializable;

/**
 * A {@code SessionKey} is a key that allows look-up of any particular {@link org.apache.shiro.session.Session Session}
 * instance.  This is not to be confused what is probably better recognized as a session <em>attribute</em> key - a key
 * that is used to acquire a session attribute via the
 * {@link org.apache.shiro.session.Session#getAttribute(Object) Session.getAttribute} method.  A {@code SessionKey}
 * looks up a Session object directly.
 * <p/>
 * While a {@code SessionKey} allows lookup of <em>any</em> Session that might exist, this is not something in practice
 * done too often by most Shiro end-users.  Instead, it is usually more convenient to acquire the currently executing
 * {@code Subject}'s session via the {@link org.apache.shiro.subject.Subject#getSession} method.  This interface and
 * its usages are best suited for framework development.
 *
 * @since 1.0
 */
public interface SessionKey {

    /**
     * Returns the id of the session to acquire.
     * <p/>
     * Acquiring sessions by ID only is a suitable strategy when sessions are natively managed by Shiro directly.
     * For example, the Servlet specification does not have an API that allows session acquisition by session ID, so
     * the session ID alone is not sufficient for ServletContainer-based SessionManager implementations.
     *
     * @return the id of the session to acquire.
     */
    Serializable getSessionId();
}
