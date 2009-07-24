package org.apache.shiro.web;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.ReplacedSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractSessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import static org.easymock.EasyMock.*;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.UUID;

/**
 * Unit test for the {@link org.apache.shiro.web.DelegatingWebSecurityManager} implementation.
 *
 * @since 1.0
 */
public class DelegatingWebSecurityManagerTest {

    private DelegatingWebSecurityManager sm;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DelegatingWebSecurityManager();
        ThreadContext.bind(sm);
    }

    @After
    public void tearDown() {
        sm.destroy();
        ThreadContext.clear();
    }

    protected void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testSessionTimeout() {

        SecurityManager delegate = createMock(SecurityManager.class);
        sm.setDelegateSecurityManager(delegate);

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        InetAddress host;
        try {
            host = InetAddress.getByName("192.168.1.1");
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }

        Serializable sessionId = UUID.randomUUID().toString();
        expect(delegate.start((Map) null)).andReturn(sessionId);
        expect(delegate.getHostAddress(sessionId)).andReturn(host);
        expect(delegate.getTimeout(sessionId)).andReturn(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        delegate.setTimeout(sessionId, 125);
        expectLastCall().times(1);
        expect(delegate.getTimeout(sessionId)).andReturn(125L);
        //pretend that 125ms have gone by
        Serializable replacedSessionId = UUID.randomUUID().toString();
        @SuppressWarnings({"ThrowableInstanceNeverThrown"})
        ReplacedSessionException replaced =
                new ReplacedSessionException("test", new ExpiredSessionException(sessionId),
                        sessionId, replacedSessionId);
        expect(delegate.getTimeout(sessionId)).andThrow(replaced);
        //the DelegatingSession will re-try the call on a ReplacedSessionException
        expect(delegate.getHostAddress(replacedSessionId)).andReturn(host);
        expect(delegate.getTimeout(replacedSessionId)).andReturn(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);

        replay(delegate);
        replay(mockRequest);

        Subject subject = sm.getSubject();
        Session session = subject.getSession();
        String id = session.getId().toString();
        assertEquals(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT, session.getTimeout());
        session.setTimeout(125);
        assertEquals(125, session.getTimeout());
        //sleep(175);
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        long timeout = session.getTimeout();
        assertEquals(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT, timeout);
        assertFalse(id.equals(session.getId())); //new ID would have been generated

        verify(delegate);
        verify(mockRequest);
    }
}
