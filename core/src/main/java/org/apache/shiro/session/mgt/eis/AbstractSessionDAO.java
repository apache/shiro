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
package org.apache.shiro.session.mgt.eis;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.SimpleSession;

import java.io.Serializable;


/**
 * An abstract {@code SessionDAO} implementation that performs some sanity checks on session creation and reading and
 * allows for pluggable Session ID generation strategies if desired.  The {@code SessionDAO}
 * {@link SessionDAO#update update} and {@link SessionDAO#delete delete} methods are left to
 * subclasses.
 * <h3>Session ID Generation</h3>
 * This class also allows for plugging in a {@link SessionIdGenerator} for custom ID generation strategies.  This is
 * optional, as the default generator is probably sufficient for most cases.  Subclass implementations that do use a
 * generator (default or custom) will want to call the
 * {@link #generateSessionId(org.apache.shiro.session.Session)} method from within their {@link #doCreate}
 * implementations.
 * <p/>
 * Subclass implementations that rely on the EIS data store to generate the ID automatically (e.g. when the session
 * ID is also an auto-generated primary key), they can simply ignore the {@code SessionIdGenerator} concept
 * entirely and just return the data store's ID from the {@link #doCreate} implementation.
 *
 * @since 1.0
 */
public abstract class AbstractSessionDAO implements SessionDAO {

    /**
     * Optional SessionIdGenerator instance available to subclasses via the
     * {@link #generateSessionId(org.apache.shiro.session.Session)} method.
     */
    private SessionIdGenerator sessionIdGenerator;

    /**
     * Default no-arg constructor that defaults the {@link #setSessionIdGenerator sessionIdGenerator} to be a
     * {@link org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator}.
     */
    public AbstractSessionDAO() {
        this.sessionIdGenerator = new JavaUuidSessionIdGenerator();
    }

    /**
     * Returns the {@code SessionIdGenerator} used by the {@link #generateSessionId(org.apache.shiro.session.Session)}
     * method.  Unless overridden by the {@link #setSessionIdGenerator(SessionIdGenerator)} method, the default instance
     * is a {@link JavaUuidSessionIdGenerator}.
     *
     * @return the {@code SessionIdGenerator} used by the {@link #generateSessionId(org.apache.shiro.session.Session)}
     *         method.
     */
    public SessionIdGenerator getSessionIdGenerator() {
        return sessionIdGenerator;
    }

    /**
     * Sets the {@code SessionIdGenerator} used by the {@link #generateSessionId(org.apache.shiro.session.Session)}
     * method.  Unless overridden by this method, the default instance ss a {@link JavaUuidSessionIdGenerator}.
     *
     * @param sessionIdGenerator the {@code SessionIdGenerator} to use in the
     *                           {@link #generateSessionId(org.apache.shiro.session.Session)} method.
     */
    public void setSessionIdGenerator(SessionIdGenerator sessionIdGenerator) {
        this.sessionIdGenerator = sessionIdGenerator;
    }

    /**
     * Generates a new ID to be applied to the specified {@code session} instance.  This method is usually called
     * from within a subclass's {@link #doCreate} implementation where they assign the returned id to the session
     * instance and then create a record with this ID in the EIS data store.
     * <p/>
     * Subclass implementations backed by EIS data stores that auto-generate IDs during record creation, such as
     * relational databases, don't need to use this method or the {@link #getSessionIdGenerator() sessionIdGenerator}
     * attribute - they can simply return the data store's generated ID from the {@link #doCreate} implementation
     * if desired.
     * <p/>
     * This implementation uses the {@link #setSessionIdGenerator configured} {@link SessionIdGenerator} to create
     * the ID.
     *
     * @param session the new session instance for which an ID will be generated and then assigned
     * @return the generated ID to assign
     */
    protected Serializable generateSessionId(Session session) {
        if (this.sessionIdGenerator == null) {
            String msg = "sessionIdGenerator attribute has not been configured.";
            throw new IllegalStateException(msg);
        }
        return this.sessionIdGenerator.generateId(session);
    }

    /**
     * Creates the session by delegating EIS creation to subclasses via the {@link #doCreate} method, and then
     * asserting that the returned sessionId is not null.
     *
     * @param session Session object to create in the EIS and associate with an ID.
     */
    public Serializable create(Session session) {
        Serializable sessionId = doCreate(session);
        verifySessionId(sessionId);
        return sessionId;
    }

    /**
     * Ensures the sessionId returned from the subclass implementation of {@link #doCreate} is not null and not
     * already in use.
     *
     * @param sessionId session id returned from the subclass implementation of {@link #doCreate}
     */
    private void verifySessionId(Serializable sessionId) {
        if (sessionId == null) {
            String msg = "sessionId returned from doCreate implementation is null.  Please verify the implementation.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Utility method available to subclasses that wish to
     * assign a generated session ID to the session instance directly.  This method is not used by the
     * {@code AbstractSessionDAO} implementation directly, but it is provided so subclasses don't
     * need to know the {@code Session} implementation if they don't need to.
     * <p/>
     * This default implementation casts the argument to a {@link SimpleSession}, Shiro's default EIS implementation.
     *
     * @param session   the session instance to which the sessionId will be applied
     * @param sessionId the id to assign to the specified session instance.
     */
    protected void assignSessionId(Session session, Serializable sessionId) {
        ((SimpleSession) session).setId(sessionId);
    }

    /**
     * Subclass hook to actually persist the given <tt>Session</tt> instance to the underlying EIS.
     *
     * @param session the Session instance to persist to the EIS.
     * @return the id of the session created in the EIS (i.e. this is almost always a primary key and should be the
     *         value returned from {@link org.apache.shiro.session.Session#getId() Session.getId()}.
     */
    protected abstract Serializable doCreate(Session session);

    /**
     * Retrieves the Session object from the underlying EIS identified by <tt>sessionId</tt> by delegating to
     * the {@link #doReadSession(java.io.Serializable)} method.  If {@code null} is returned from that method, an
     * {@link UnknownSessionException} will be thrown.
     *
     * @param sessionId the id of the session to retrieve from the EIS.
     * @return the session identified by <tt>sessionId</tt> in the EIS.
     * @throws UnknownSessionException if the id specified does not correspond to any session in the EIS.
     */
    public Session readSession(Serializable sessionId) throws UnknownSessionException {
        Session s = doReadSession(sessionId);
        if (s == null) {
            throw new UnknownSessionException("There is no session with id [" + sessionId + "]");
        }
        return s;
    }

    /**
     * Subclass implementation hook that retrieves the Session object from the underlying EIS or {@code null} if a
     * session with that ID could not be found.
     *
     * @param sessionId the id of the <tt>Session</tt> to retrieve.
     * @return the Session in the EIS identified by <tt>sessionId</tt> or {@code null} if a
     *         session with that ID could not be found.
     */
    protected abstract Session doReadSession(Serializable sessionId);

}
