package org.apache.shiro.session.mgt;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import org.apache.shiro.util.ThreadContext;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * Unit test for the {@link DelegatingSession} class.
 */
public class DelegatingSessionTest {

    DelegatingSession session = null;
    DefaultSessionManager sm = null;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DefaultSessionManager();
        Serializable sessionId = sm.start((InetAddress)null);
        this.session = new DelegatingSession(sm, sessionId);
    }

    @After
    public void tearDown() {
        sm.destroy();
        ThreadContext.clear();
    }

    public void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testTimeout() {
        Serializable origId = session.getId();
        assertEquals(session.getTimeout(), AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        session.setTimeout(100);
        assertEquals(session.getTimeout(), 100);
        sleep(100);
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        assertEquals(session.getTimeout(), AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        assertFalse(origId.equals(session.getId())); //new ID would have been generated
    }

}
