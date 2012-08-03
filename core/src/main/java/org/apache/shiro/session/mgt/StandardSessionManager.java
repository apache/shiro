package org.apache.shiro.session.mgt;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.event.Publisher;
import org.apache.shiro.session.*;
import org.apache.shiro.session.event.InvalidSessionEvent;
import org.apache.shiro.session.event.SessionEvent;
import org.apache.shiro.session.event.StartedSessionEvent;
import org.apache.shiro.session.event.StoppedSessionEvent;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.util.Assert;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.Destroyable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

/**
 * @since 1.3
 */
public class StandardSessionManager implements NativeSessionManager, ValidatingSessionManager, CacheManagerAware, Destroyable {

    private static final Logger log = LoggerFactory.getLogger(StandardSessionManager.class);

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    public static final long DEFAULT_SESSION_TIMEOUT = 30 * MILLIS_PER_MINUTE; //30 minutes

    private long defaultSessionTimeout = DEFAULT_SESSION_TIMEOUT;
    private boolean deleteInvalidSessions;
    private SessionValidationScheduler sessionValidationScheduler;
    protected SessionFactory sessionFactory;
    protected SessionDAO sessionDAO;
    protected CacheManager cacheManager;
    protected Publisher publisher;

    public StandardSessionManager() {
        this.sessionValidationScheduler = new ExecutorServiceSessionValidationScheduler(this);
        this.deleteInvalidSessions = true;
        this.sessionFactory = new SimpleSessionFactory();
        this.sessionDAO = new MemorySessionDAO();
    }

    public long getDefaultSessionTimeout() {
        return this.defaultSessionTimeout;
    }

    public void setDefaultSessionTimeout(long defaultSessionTimeout) {
        this.defaultSessionTimeout = defaultSessionTimeout;
    }

    /**
     * Returns {@code true} if sessions should be automatically deleted after they are discovered to be invalid,
     * {@code false} if invalid sessions will be manually deleted by some process external to Shiro's control.  The
     * default is {@code true} to ensure no orphans exist in the underlying data store.
     * <h4>Usage</h4>
     * It is ok to set this to {@code false} <b><em>ONLY</em></b> if you have some other process that you manage yourself
     * that periodically deletes invalid sessions from the backing data store over time, such as via a Quartz or Cron
     * job.  If you do not do this, the invalid sessions will become 'orphans' and fill up the data store over time.
     * <p/>
     * This property is provided because some systems need the ability to perform querying/reporting against sessions in
     * the data store, even after they have stopped or expired.  Setting this attribute to {@code false} will allow
     * such querying, but with the caveat that the application developer/configurer deletes the sessions themselves by
     * some other means (cron, quartz, etc).
     *
     * @return {@code true} if sessions should be automatically deleted after they are discovered to be invalid,
     *         {@code false} if invalid sessions will be manually deleted by some process external to Shiro's control.
     */
    public boolean isDeleteInvalidSessions() {
        return deleteInvalidSessions;
    }

    /**
     * Sets whether or not sessions should be automatically deleted after they are discovered to be invalid.  Default
     * value is {@code true} to ensure no orphans will exist in the underlying data store.
     * <h4>WARNING</h4>
     * Only set this value to {@code false} if you are manually going to delete sessions yourself by some process
     * (quartz, cron, etc) external to Shiro's control.  See the
     * {@link #isDeleteInvalidSessions() isDeleteInvalidSessions()} JavaDoc for more.
     *
     * @param deleteInvalidSessions whether or not sessions should be automatically deleted after they are discovered
     *                              to be invalid.
     */
    @SuppressWarnings("UnusedDeclaration")
    public void setDeleteInvalidSessions(boolean deleteInvalidSessions) {
        this.deleteInvalidSessions = deleteInvalidSessions;
    }

    public SessionValidationScheduler getSessionValidationScheduler() {
        return sessionValidationScheduler;
    }

    public void setSessionValidationScheduler(SessionValidationScheduler sessionValidationScheduler) {
        this.sessionValidationScheduler = sessionValidationScheduler;
    }

    public SessionDAO getSessionDAO() {
        return this.sessionDAO;
    }

    public void setSessionDAO(SessionDAO sessionDAO) {
        this.sessionDAO = sessionDAO;
        applyCacheManagerToSessionDAO();
    }

    @SuppressWarnings("UnusedDeclaration")
    public CacheManager getCacheManager() {
        return this.cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        applyCacheManagerToSessionDAO();
    }

    /**
     * Sets the internal {@code CacheManager} on the {@code SessionDAO} if it implements the
     * {@link org.apache.shiro.cache.CacheManagerAware CacheManagerAware} interface.
     * <p/>
     * This method is called after setting a cacheManager via the
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) setCacheManager} method <em>em</em> when
     * setting a {@code SessionDAO} via the {@link #setSessionDAO} method to allow it to be propagated
     * in either case.
     */
    private void applyCacheManagerToSessionDAO() {
        if (this.cacheManager != null && this.sessionDAO != null && this.sessionDAO instanceof CacheManagerAware) {
            ((CacheManagerAware) this.sessionDAO).setCacheManager(this.cacheManager);
        }
    }

    /**
     * Returns the {@code SessionFactory} used to generate new {@link Session} instances.  The default instance
     * is a {@link SimpleSessionFactory}.
     *
     * @return the {@code SessionFactory} used to generate new {@link Session} instances.
     */
    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    /**
     * Sets the {@code SessionFactory} used to generate new {@link Session} instances.  The default instance
     * is a {@link SimpleSessionFactory}.
     *
     * @param sessionFactory the {@code SessionFactory} used to generate new {@link Session} instances.
     */
    @SuppressWarnings("UnusedDeclaration")
    public void setSessionFactory(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @SuppressWarnings("UnusedDeclaration")
    public Publisher getPublisher() {
        return publisher;
    }

    @SuppressWarnings("UnusedDeclaration")
    public void setPublisher(Publisher publisher) {
        this.publisher = publisher;
    }

    /* =====================================================================
       Destroyable implementation
       ===================================================================== */

    public void destroy() throws Exception {
        if (this.sessionValidationScheduler != null) {
            this.sessionValidationScheduler.disableSessionValidation();
        }
    }

    /* =====================================================================
       SessionManager implementation
       ===================================================================== */

    public Session start(SessionContext context) {
        enableSessionValidationIfNecessary();
        Session internal = createInternalSession(context);
        //Don't expose the EIS-tier Session object to the client-tier:
        return createExposedSession(internal, context);
    }

    protected Session createInternalSession(SessionContext context) {

        Session session = getSessionFactory().createSession(context);
        if (log.isTraceEnabled()) {
            log.trace("Creating session for host {}", session.getHost());
        }

        session.setTimeout(getDefaultSessionTimeout());

        if (log.isDebugEnabled()) {
            log.debug("Creating new EIS record for new session instance [" + session + "]");
        }

        createInternalSession(session, context);

        StartedSessionEvent event = new StartedSessionEvent(session, context);
        notify(event);

        return session;
    }

    protected void createInternalSession(Session session, SessionContext context) {
        getSessionDAO().create(session);
    }

    public Session getSession(SessionKey key) throws SessionException {
        enableSessionValidationIfNecessary();
        Session session = getInternalSession(key);
        return session != null ? createExposedSession(session, key) : null;
    }

    protected Session getInternalSession(SessionKey key) {

        log.trace("Attempting to retrieve session with key {}", key);

        Serializable sessionId = getSessionId(key);
        if (sessionId == null) {
            log.debug("Unable to resolve session ID from SessionKey [{}].  Returning null to indicate a " +
                    "session could not be found.", key);
            return null;
        }
        Session session = getInternalSession(key, sessionId);
        if (session == null) {
            //session ID was provided, meaning one is expected to be found, but we couldn't find one:
            String msg = "Could not find session with ID [" + sessionId + "]";
            throw new UnknownSessionException(msg);
        }

        validate(session, key);

        return session;
    }

    protected Session getInternalSession(SessionKey sessionKey, Serializable resolvedSessionId) {
        return getSessionDAO().readSession(resolvedSessionId);
    }

    protected final void enableSessionValidationIfNecessary() {
        if (this.sessionValidationScheduler != null && !this.sessionValidationScheduler.isEnabled()) {
            this.sessionValidationScheduler.enableSessionValidation();
        }
    }

    protected Serializable getSessionId(SessionKey sessionKey) {
        return sessionKey.getSessionId();
    }

    /* =====================================================================
       ValidatingSessionManager methods
       ===================================================================== */

    public void validateSessions() {
        log.debug("Validating active sessions...");

        Collection<Session> activeSessions = getSessionDAO().getActiveSessions();
        int invalidCount = validate(activeSessions);

        if (log.isDebugEnabled()) {
            String msg = "Finished session validation.";
            if (invalidCount > 0) {
                msg += "  [" + invalidCount + "] sessions were stopped.";
            } else {
                msg += "  No sessions were stopped.";
            }
            log.debug(msg);
        }
    }

    protected int validate(Collection<Session> activeSessions) {

        int invalidCount = 0;

        if (activeSessions != null) {
            for (Session s : activeSessions) {
                try {
                    //simulate a lookup key to satisfy the method signature.
                    //this could probably stand to be cleaned up in future versions:
                    SessionKey key = new DefaultSessionKey(s.getId());
                    validate(s, key);
                } catch (InvalidSessionException e) {
                    if (log.isTraceEnabled()) {
                        boolean expired = (e instanceof ExpiredSessionException);
                        String msg = "Invalidated session with id [" + s.getId() + "]" +
                                (expired ? " (expired)" : " (stopped)");
                        log.trace(msg);
                    }
                    invalidCount++;
                }
            }
        }

        return invalidCount;
    }

    protected void validate(Session session, SessionKey key) throws InvalidSessionException {
        Assert.isInstanceOf(ValidatingSession.class, session, StandardSessionManager.class.getName() +
                " implementations require native sessions to implement " + ValidatingSession.class.getName());

        try {
            ((ValidatingSession) session).validate();
        } catch (InvalidSessionException ise) {
            onStop(session, key, ise);
            throw ise;
        }
    }

    protected void onStop(Session session, SessionKey key, InvalidSessionException ise) {

        boolean expired = ise instanceof ExpiredSessionException;

        if (session instanceof SimpleSession) {
            SimpleSession ss = (SimpleSession) session;
            if (expired) {
                ss.setExpired(expired);
            } else {
                Date stopTs = ss.getStopTimestamp();
                ss.setLastAccessTime(stopTs);
            }
        }

        Session immutable = beforeStopNotification(session);
        SessionEvent event = (ise != null) ?
                new InvalidSessionEvent(immutable, key, ise) :
                new StoppedSessionEvent(immutable, key);
        notify(event);

        if (isDeleteInvalidSessions()) {
            delete(session, key);
        } else {
            update(session, key);
        }
    }

    protected void delete(Session session, SessionKey key) {
        log.debug("Deleting DAO session {}", session.getId());
        getSessionDAO().delete(session);
    }

    protected void update(Session session, SessionKey key) {
        log.debug("Updating DAO session {}", session.getId());
        getSessionDAO().update(session);
    }

    @SuppressWarnings("unchecked")
    protected void notify(Object event) {
        if (event != null && this.publisher != null) {
            this.publisher.publish(event);
        }
    }

    protected Session createExposedSession(Session session, Object context) {
        return new DelegatingSession(this, new DefaultSessionKey(session.getId()));
    }

    /**
     * Returns the session instance to use to pass to registered {@code SessionListener}s for notification
     * that the session has been stopped (stopped or expired).
     * <p/>
     * The default implementation returns an {@link ImmutableProxiedSession ImmutableProxiedSession} instance to ensure
     * that the specified {@code session} argument is not modified by any listeners.
     *
     * @param session the stopped {@code Session}.
     * @return the {@code Session} instance to use for {@link #notify(Object) notification}.
     */
    protected Session beforeStopNotification(Session session) {
        return new ImmutableProxiedSession(session);
    }

    /* =====================================================================
       NativeSessionManager implementation
       ===================================================================== */

    public Date getStartTimestamp(SessionKey key) {
        return getInternalSession(key).getStartTimestamp();
    }

    public Date getLastAccessTime(SessionKey key) {
        return getInternalSession(key).getLastAccessTime();
    }

    public long getTimeout(SessionKey key) throws InvalidSessionException {
        return getInternalSession(key).getTimeout();
    }

    public void setTimeout(SessionKey key, long maxIdleTimeInMillis) throws InvalidSessionException {
        Session session = getInternalSession(key);
        session.setTimeout(maxIdleTimeInMillis);
        update(session, key);
    }

    public void touch(SessionKey key) throws InvalidSessionException {
        Session session = getInternalSession(key);
        session.touch();
        update(session, key);
    }

    public String getHost(SessionKey key) {
        return getInternalSession(key).getHost();
    }

    public Collection<Object> getAttributeKeys(SessionKey key) {
        Collection<Object> c = getInternalSession(key).getAttributeKeys();
        if (!CollectionUtils.isEmpty(c)) {
            return Collections.unmodifiableCollection(c);
        }
        return Collections.emptySet();
    }

    public Object getAttribute(SessionKey sessionKey, Object attributeKey) throws InvalidSessionException {
        return getInternalSession(sessionKey).getAttribute(attributeKey);
    }

    public void setAttribute(SessionKey key, Object attributeKey, Object value) throws InvalidSessionException {
        if (value == null) {
            removeAttribute(key, attributeKey);
        } else {
            Session s = getInternalSession(key);
            s.setAttribute(attributeKey, value);
            update(s, key);
        }
    }

    public Object removeAttribute(SessionKey key, Object attributeKey) throws InvalidSessionException {
        Session session = getInternalSession(key);
        Object removed = session.removeAttribute(attributeKey);
        if (removed != null) {
            update(session, key);
        }
        return removed;
    }

    public boolean isValid(SessionKey key) {
        try {
            checkValid(key);
            return true;
        } catch (InvalidSessionException e) {
            return false;
        }
    }

    public void stop(SessionKey key) throws InvalidSessionException {
        Session session = getInternalSession(key);
        if (log.isDebugEnabled()) {
            log.debug("Stopping session with id [" + session.getId() + "]");
        }
        session.stop();
        onStop(session, key, null);
    }

    public void checkValid(SessionKey key) throws InvalidSessionException {
        //just try to acquire it.  If there is a problem, an exception will be thrown:
        getInternalSession(key);
    }
}
