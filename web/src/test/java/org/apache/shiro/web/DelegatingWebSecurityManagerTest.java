package org.apache.shiro.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.apache.shiro.session.Session;
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

/**
 * Unit test for the {@link org.apache.shiro.web.DelegatingWebSecurityManager} implementation.
 *
 * @since 1.0
 */
public class DelegatingWebSecurityManagerTest {

    private DefaultSecurityManager delegate;
    private DelegatingWebSecurityManager sm;

    @Before
    public void setup() {
        delegate = new DefaultSecurityManager();
        delegate.setRealm(new PropertiesRealm());
        sm = new DelegatingWebSecurityManager();
        sm.setDelegateSecurityManager(delegate);
        SecurityUtils.setSecurityManager(sm);
        ThreadContext.clear();
    }

    @After
    public void tearDown() {
        sm.destroy();
        delegate.destroy();
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
        long globalTimeout = 100;
        delegate.setGlobalSessionTimeout(globalTimeout);

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        replay(mockRequest);

        Subject subject = sm.getSubject();
        Session session = subject.getSession();
        Serializable origId = session.getId();
        assertEquals(globalTimeout, session.getTimeout());
        session.setTimeout(125);
        assertEquals(125, session.getTimeout());
        sleep(175);
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        assertEquals(globalTimeout, session.getTimeout());
        assertFalse(origId.equals(session.getId())); //new ID would have been generated
    }
}
