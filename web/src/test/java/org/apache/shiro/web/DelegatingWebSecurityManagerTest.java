package org.apache.shiro.web;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Jul 18, 2009
 * Time: 7:46:22 PM
 * To change this template use File | Settings | File Templates.
 */
public class DelegatingWebSecurityManagerTest {

    private DefaultSecurityManager delegate;
    private DelegatingWebSecurityManager sm;

    @Before
    public void setup() {
        delegate = new DefaultSecurityManager();
        delegate.setRealm(new PropertiesRealm());
        delegate.setGlobalSessionTimeout(-1);
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
        long globalTimeout = -1;

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
        assertEquals(session.getTimeout(), globalTimeout);
        session.setTimeout(100);
        assertEquals(session.getTimeout(), 100);
        sleep(150);
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        assertEquals(session.getTimeout(), globalTimeout);
        assertFalse(origId.equals(session.getId())); //new ID would have been generated

        //verify(mockRequest);
    }
}
