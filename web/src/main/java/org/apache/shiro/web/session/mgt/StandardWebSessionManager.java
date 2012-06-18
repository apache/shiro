package org.apache.shiro.web.session.mgt;

import org.apache.shiro.event.Subscriber;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.*;
import org.apache.shiro.util.Assert;
import org.apache.shiro.web.event.BeginServletRequestEvent;
import org.apache.shiro.web.event.EndServletRequestEvent;
import org.apache.shiro.web.servlet.*;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @since 1.3
 */
public class StandardWebSessionManager extends StandardSessionManager implements WebSessionManager, Subscriber {

    private static final Logger log = LoggerFactory.getLogger(StandardWebSessionManager.class);

    private static final String REQUEST_ID_ATTR_NAME = "ApacheShiroRequestId";

    private static final String REFERENCED_SESSION_IDS = DefaultWebSessionManager.class.getName() + ".REFERENCED_SESSION_IDS";

    private Cookie sessionIdCookie;
    private boolean sessionIdCookieEnabled;
    private AccessTimestampEvaluator accessTimestampEvaluator;
    private RequestIdGenerator requestIdGenerator;


    // The sessions actively referenced by this particular SessionManager node.  Sessions are only present in this
    // collection if they are being currently referenced by active requests serviced by this particular node.
    //
    // This collection effectively acts as a first-level cache in front of the SessionDAO:  Session state changes are
    // persisted to the SessionDAO only when:
    //     1. there are no requests currently associated with the session and
    //     2. when the last referencing request completes.
    //
    // This alleviates the potential constant 'hit' on SessionDAO back-end data stores that might not support
    // first-level caching themselves.
    //
    // The SessionDAO is used for durable storage.
    //
    // key: session id, value: currently-in-use-session
    private final ConcurrentMap<Serializable, Session> activeSessions;

    //The number of requests interacting with a particular session in this node.  When the number of references
    //is 0, the count is removed from this collection to ensure memory remains reasonable.
    //key: sessionID, value: total count of all requests currently interacting with the session identified by sessionId
    private final ConcurrentMap<Serializable, AtomicInteger> activeSessionRequestCounts;

    public StandardWebSessionManager() {
        super();
        Cookie cookie = new SimpleCookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        cookie.setHttpOnly(true); //more secure, protects against XSS attacks
        this.sessionIdCookie = cookie;
        this.sessionIdCookieEnabled = true;
        this.accessTimestampEvaluator = new SpecCompliantAccessTimestampEvaluator();
        this.requestIdGenerator = new UuidRequestIdGenerator();
        this.activeSessions = new ConcurrentHashMap<Serializable, Session>();
        this.activeSessionRequestCounts = new ConcurrentHashMap<Serializable, AtomicInteger>();
    }

    public Cookie getSessionIdCookie() {
        return sessionIdCookie;
    }

    public boolean isSessionIdCookieEnabled() {
        return sessionIdCookieEnabled;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookie(Cookie sessionIdCookie) {
        this.sessionIdCookie = sessionIdCookie;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookieEnabled(boolean sessionIdCookieEnabled) {
        this.sessionIdCookieEnabled = sessionIdCookieEnabled;
    }

    public AccessTimestampEvaluator getAccessTimestampEvaluator() {
        return accessTimestampEvaluator;
    }

    @SuppressWarnings("UnusedDeclaration")
    public void setAccessTimestampEvaluator(AccessTimestampEvaluator accessTimestampEvaluator) {
        this.accessTimestampEvaluator = accessTimestampEvaluator;
    }

    public RequestIdGenerator getRequestIdGenerator() {
        return requestIdGenerator;
    }

    @SuppressWarnings("UnusedDeclaration")
    public void setRequestIdGenerator(RequestIdGenerator requestIdGenerator) {
        this.requestIdGenerator = requestIdGenerator;
    }

    private void storeSessionId(Serializable currentId, HttpServletRequest request, HttpServletResponse response) {
        Assert.notNull(currentId, "sessionId argument cannot be null.");

        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);

        String id = String.valueOf(currentId);
        cookie.setValue(id);
        cookie.saveTo(request, response);

        log.trace("Set session ID cookie for session with id {}", id);
    }

    private String getSessionIdCookieValue(ServletRequest request, ServletResponse response) {
        if (isSessionIdCookieEnabled() && request instanceof HttpServletRequest) {
            return getSessionIdCookie().readValue(WebUtils.toHttp(request), WebUtils.toHttp(response));
        }
        return null;
    }

    @Override
    protected Session createExposedSession(Session session, Object httpPair) {
        if (!WebUtils.isWeb(httpPair)) {
            return super.createExposedSession(session, httpPair);
        }
        ServletRequest request = WebUtils.getRequest(httpPair);
        ServletResponse response = WebUtils.getResponse(httpPair);
        SessionKey sessionKey = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, sessionKey);
    }

    @Override
    protected void createInternalSession(Session session, SessionContext context) {
        super.createInternalSession(session, context);

        if (WebUtils.isHttp(context)) {
            HttpServletRequest request = WebUtils.getHttpRequest(context);
            HttpServletResponse response = WebUtils.getHttpResponse(context);
            log.trace("Request ID: {}, Created Session {}", request.getAttribute(AbstractShiroFilter.REQUEST_ID_ATTR_NAME), session.getId());

            if (isSessionIdCookieEnabled()) {
                Serializable sessionId = session.getId();
                storeSessionId(sessionId, request, response);
            } else {
                log.debug("Session ID cookie is disabled.  No cookie has been set for new session with id {}", session.getId());
            }

            request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);

            addSessionReference(request, session);
        }
    }

    @Override
    protected Session getInternalSession(SessionKey key, Serializable sessionId) {
        HttpServletRequest request = WebUtils.isHttp(key) ? WebUtils.getHttpRequest(key) : null;

        //activeSessions is a request-specific concept.  Only reference it if in the context of a request:
        if (request == null) {
            return super.getInternalSession(key, sessionId);
        }

        Session internal = activeSessions.get(sessionId);
        if (internal == null) {
            //not in first-level request cache, check the DAO:
            internal = super.getInternalSession(key, sessionId);
            if (internal != null) {
                //found it.  Update the reference count for post-request cleanup:
                addSessionReference(request, internal);
            }
        } else {
            //in first-level request cache.  Update the reference count for post-request cleanup:
            addSessionReference(request, internal.getId());
        }


        return internal;
    }

    private void addSessionReference(HttpServletRequest request, Session session) {
        Serializable id = session.getId();
        addSessionReference(request, id);
        this.activeSessions.put(id, session);
    }

    @SuppressWarnings("unchecked")
    private void addSessionReference(HttpServletRequest request, Serializable sessionId) {
        Set<Serializable> ids = (Set<Serializable>) request.getAttribute(REFERENCED_SESSION_IDS);
        if (ids == null) {
            ids = new CopyOnWriteArraySet<Serializable>();
            request.setAttribute(REFERENCED_SESSION_IDS, ids);
        }
        boolean added = ids.add(sessionId);
        if (added) {
            incrementReferencedSession(sessionId);
        }
    }

    private int incrementReferencedSession(Serializable sessionId) {
        AtomicInteger count = this.activeSessionRequestCounts.get(sessionId);
        if (count == null) {
            count = new AtomicInteger(0);
            AtomicInteger previous = this.activeSessionRequestCounts.putIfAbsent(sessionId, count);
            if (previous != null) {
                count = previous;
            }
        }
        return count.incrementAndGet();
    }

    @Override
    protected void update(Session session, SessionKey key) {
        if (!WebUtils.isHttp(key)) {
            super.update(session, key);
            return;
        }
        //don't actually update - we'll defer that to the end of the request via
        //onEvent(EndServletRequestEvent).  Just keep a record that it is referenced for now:
        HttpServletRequest request = WebUtils.getHttpRequest(key);
        addSessionReference(request, session);
        log.trace("Ignored mid-request DAO update.  Update will occur at the end of the request.");
    }

    public void onEvent(Object event) {
        if (event instanceof BeginServletRequestEvent) {
            handle((BeginServletRequestEvent)event);
        } else if (event instanceof EndServletRequestEvent) {
            handle((EndServletRequestEvent)event);
        }
    }

    private void handle(BeginServletRequestEvent event) {
        //give the request a unique ID, useful for multi-threaded debugging:
        assignRequestId(event);

        //update any associated session's last access timestamp to ensure sessions timeout:
        updateSessionLastAccessTimestampIfPossible(event);
    }

    private void assignRequestId(BeginServletRequestEvent event) {
        RequestIdGenerator generator = getRequestIdGenerator();
        if (generator != null) {
            String id = generator.generateId(event);
            if (id != null) {
                event.getServletRequest().setAttribute(REQUEST_ID_ATTR_NAME, id);
            }
        }
    }

    private void updateSessionLastAccessTimestampIfPossible(BeginServletRequestEvent event) {
        Session session = event.getSubject().getSession(false);
        if (session != null) {
            AccessTimestampEvaluator evaluator = getAccessTimestampEvaluator();
            if (evaluator == null || evaluator.isUpdateAccessTimestamp(event)) {
                try {
                    session.touch();
                } catch (Throwable t) {
                    log.error("session.touch() method invocation has failed.  Unable to update" +
                            "the corresponding session's last access time based on the incoming request.", t);
                }
            }
        }
    }

    protected final void handle(EndServletRequestEvent event) {
        ServletRequest request = event.getServletRequest();
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            dereferenceSessions(httpRequest);
        }
    }

    @SuppressWarnings("unchecked")
    private void dereferenceSessions(HttpServletRequest request) {
        Set<Serializable> ids = (Set<Serializable>) request.getAttribute(REFERENCED_SESSION_IDS);
        if (ids == null) {
            return;
        }

        for (Serializable id : ids) {
            int count = decrementReferencedSession(id);
            if (count <= 0) {
                String requestId = (String)request.getAttribute(AbstractShiroFilter.REQUEST_ID_ATTR_NAME);
                Session session = activeSessions.remove(id);
                if (session instanceof ValidatingSession) {
                    ValidatingSession vs = (ValidatingSession) session;
                    if (!vs.isValid() && isDeleteInvalidSessions()) {
                        getSessionDAO().delete(vs);
                        log.trace("Request ID: {}, Deleted DAO Session {}", requestId, id);
                    } else {
                        getSessionDAO().update(vs);
                        log.trace("Request ID: {}, Updated DAO Session {}", requestId, id);
                    }
                } else {
                    getSessionDAO().update(session);
                    log.trace("Request ID: {}, Updated DAO Session {}", requestId, id);
                }
            }
        }
    }

    private int decrementReferencedSession(Serializable sessionId) {
        AtomicInteger count = this.activeSessionRequestCounts.get(sessionId);
        if (count != null) {
            int val = count.decrementAndGet();
            if (val <= 0) {
                this.activeSessionRequestCounts.remove(sessionId);
            }
            return val;
        }
        return 0;
    }


    @Override
    public Serializable getSessionId(SessionKey key) {
        Serializable id = super.getSessionId(key);
        if (id == null && WebUtils.isWeb(key)) {
            ServletRequest request = WebUtils.getRequest(key);
            ServletResponse response = WebUtils.getResponse(key);
            id = getSessionId(request, response);
        }
        return id;
    }

    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        String id = getSessionIdCookieValue(request, response);
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    ShiroHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        } else {
            //not in a cookie, or cookie is disabled - try the request params as a fallback (i.e. URL rewriting):
            id = request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
            if (id == null) {
                //try lowercase:
                id = request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME.toLowerCase());
            }
            if (id != null) {
                request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                        ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
            }
        }
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            //automatically mark it valid here.  If it is invalid, the
            //onUnknownSession method below will be invoked and we'll remove the attribute at that time.
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        }
        return id;
    }

    @Override
    protected void onStop(Session session, SessionKey key, InvalidSessionException ise) {
        super.onStop(session, key, ise);

        if (WebUtils.isHttp(key)) {
            HttpServletRequest request = WebUtils.getHttpRequest(key);
            HttpServletResponse response = WebUtils.getHttpResponse(key);
            if (ise != null) {
                request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
            }
            log.debug("Session is stopped or invalid.  Removing session ID cookie.");
            getSessionIdCookie().removeFrom(request, response);
        }
    }

    /**
     * This is a native session manager implementation, so this method returns {@code false} always.
     *
     * @return {@code false} always
     */
    public boolean isServletContainerSessions() {
        return false;
    }
}
