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
package org.apache.ki.session.mgt;

import org.apache.ki.cache.CacheManager;
import org.apache.ki.cache.CacheManagerAware;
import org.apache.ki.session.InvalidSessionException;
import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.eis.MemorySessionDAO;
import org.apache.ki.session.mgt.eis.SessionDAO;
import org.apache.ki.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;


/**
 * Default business-tier implementation of a {@link ValidatingSessionManager}.  All session CRUD operations are
 * delegated to an internal {@link SessionDAO}.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class DefaultSessionManager extends AbstractValidatingSessionManager implements CacheManagerAware {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultSessionManager.class);

    protected SessionDAO sessionDAO;

    public DefaultSessionManager() {
        this.sessionDAO = new MemorySessionDAO();
    }

    public void setSessionDAO(SessionDAO sessionDAO) {
        this.sessionDAO = sessionDAO;
    }

    public SessionDAO getSessionDAO() {
        return this.sessionDAO;
    }

    public void setCacheManager(CacheManager cacheManager) {
        if (this.sessionDAO instanceof CacheManagerAware) {
            ((CacheManagerAware) this.sessionDAO).setCacheManager(cacheManager);
        }
    }

    protected Session doCreateSession(InetAddress originatingHost) {
        if (log.isTraceEnabled()) {
            log.trace("Creating session for originating host [" + originatingHost + "]");
        }
        Session s = newSessionInstance(originatingHost);
        create(s);
        return s;
    }

    protected Session newSessionInstance(InetAddress inetAddress) {
        return new SimpleSession(inetAddress);
    }

    protected void create(Session session) {
        if (log.isDebugEnabled()) {
            log.debug("Creating new EIS record for new session instance [" + session + "]");
        }
        sessionDAO.create(session);
    }

    protected void onStop(Session session) {
        if (session instanceof SimpleSession) {
            SimpleSession ss = (SimpleSession)session;
            Date stopTs = ss.getStopTimestamp();
            ss.setLastAccessTime(stopTs);
        }
        onChange(session);
    }

    protected void onExpiration(Session session) {
        if (session instanceof SimpleSession) {
            ((SimpleSession) session).setExpired(true);
        }
        onChange(session);
    }

    protected void onChange(Session session) {
        sessionDAO.update(session);
    }

    protected Session retrieveSession(Serializable sessionId) throws InvalidSessionException {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to retrieve session with id [" + sessionId + "]");
        }
        return retrieveSessionFromDataSource(sessionId);
    }

    protected Session retrieveSessionFromDataSource(Serializable sessionId) throws InvalidSessionException {
        return sessionDAO.readSession(sessionId);
    }

    protected Collection<Session> getActiveSessions() {
        Collection<Session> active = sessionDAO.getActiveSessions();
        return active != null ? active : CollectionUtils.emptyCollection(Session.class);
    }

}
