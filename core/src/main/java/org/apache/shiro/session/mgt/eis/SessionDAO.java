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

import java.io.Serializable;
import java.util.Collection;


/**
 * Data Access Object design pattern specification to enable {@link Session} access to an
 * EIS (Enterprise Information System).  It provides your four typical CRUD methods:
 * {@link #create}, {@link #readSession(java.io.Serializable)}, {@link #update(org.apache.shiro.session.Session)},
 * and {@link #delete(org.apache.shiro.session.Session)}.
 * <p/>
 * The remaining {@link #getActiveSessions()} method exists as a support mechanism to pre-emptively orphaned sessions,
 * typically by {@link org.apache.shiro.session.mgt.ValidatingSessionManager ValidatingSessionManager}s), and should
 * be as efficient as possible, especially if there are thousands of active sessions.  Large scale/high performance
 * implementations will often return a subset of the total active sessions and perform validation a little more
 * frequently, rather than return a massive set and infrequently validate.
 *
 * @since 0.1
 */
public interface SessionDAO {

    /**
     * Inserts a new Session record into the underling EIS (e.g. Relational database, file system, persistent cache,
     * etc, depending on the DAO implementation).
     * <p/>
     * After this method is invoked, the {@link org.apache.shiro.session.Session#getId()}
     * method executed on the argument must return a valid session identifier.  That is, the following should
     * always be true:
     * <pre>
     * Serializable id = create( session );
     * id.equals( session.getId() ) == true</pre>
     * <p/>
     * Implementations are free to throw any exceptions that might occur due to
     * integrity violation constraints or other EIS related errors.
     *
     * @param session the {@link org.apache.shiro.session.Session} object to create in the EIS.
     * @return the EIS id (e.g. primary key) of the created {@code Session} object.
     */
    Serializable create(Session session);

    /**
     * Retrieves the session from the EIS uniquely identified by the specified
     * {@code sessionId}.
     *
     * @param sessionId the system-wide unique identifier of the Session object to retrieve from
     *                  the EIS.
     * @return the persisted session in the EIS identified by {@code sessionId}.
     * @throws UnknownSessionException if there is no EIS record for any session with the
     *                                 specified {@code sessionId}
     */
    Session readSession(Serializable sessionId) throws UnknownSessionException;

    /**
     * Updates (persists) data from a previously created Session instance in the EIS identified by
     * {@code {@link Session#getId() session.getId()}}.  This effectively propagates
     * the data in the argument to the EIS record previously saved.
     * <p/>
     * In addition to UnknownSessionException, implementations are free to throw any other
     * exceptions that might occur due to integrity violation constraints or other EIS related
     * errors.
     *
     * @param session the Session to update
     * @throws org.apache.shiro.session.UnknownSessionException
     *          if no existing EIS session record exists with the
     *          identifier of {@link Session#getId() session.getSessionId()}
     */
    void update(Session session) throws UnknownSessionException;

    /**
     * Deletes the associated EIS record of the specified {@code session}.  If there never
     * existed a session EIS record with the identifier of
     * {@link Session#getId() session.getId()}, then this method does nothing.
     *
     * @param session the session to delete.
     */
    void delete(Session session);

    /**
     * Returns all sessions in the EIS that are considered active, meaning all sessions that
     * haven't been stopped/expired.  This is primarily used to validate potential orphans.
     * <p/>
     * If there are no active sessions in the EIS, this method may return an empty collection or {@code null}.
     * <h4>Performance</h4>
     * This method should be as efficient as possible, especially in larger systems where there might be
     * thousands of active sessions.  Large scale/high performance
     * implementations will often return a subset of the total active sessions and perform validation a little more
     * frequently, rather than return a massive set and validate infrequently.  If efficient and possible, it would
     * make sense to return the oldest unstopped sessions available, ordered by
     * {@link org.apache.shiro.session.Session#getLastAccessTime() lastAccessTime}.
     * <h4>Smart Results</h4>
     * <em>Ideally</em> this method would only return active sessions that the EIS was certain should be invalided.
     * Typically that is any session that is not stopped and where its lastAccessTimestamp is older than the session
     * timeout.
     * <p/>
     * For example, if sessions were backed by a relational database or SQL-92 'query-able' enterprise cache, you might
     * return something similar to the results returned by this query (assuming
     * {@link org.apache.shiro.session.mgt.SimpleSession SimpleSession}s were being stored):
     * <pre>
     * select * from sessions s where s.lastAccessTimestamp < ? and s.stopTimestamp is null
     * </pre>
     * where the {@code ?} parameter is a date instance equal to 'now' minus the session timeout
     * (e.g. now - 30 minutes).
     *
     * @return a Collection of {@code Session}s that are considered active, or an
     *         empty collection or {@code null} if there are no active sessions.
     */
    Collection<Session> getActiveSessions();
}
