package org.apache.shiro.session.mgt;

import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * Unit test for the {@link DefaultSessionManager DefaultSessionManager} implementation.
 */
public class DefaultSessionManagerTest {

    DefaultSessionManager sm = null;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DefaultSessionManager();
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
    public void testGlobalTimeout() {
        sm.setGlobalSessionTimeout(100);
        Serializable sessionId = sm.start((InetAddress) null);
        assertTrue(sm.isValid(sessionId));
        sleep(100);
        assertFalse(sm.isValid(sessionId));
    }
}
