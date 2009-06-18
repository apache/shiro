package org.apache.shiro.spring.remoting;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import static org.easymock.EasyMock.*;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.springframework.remoting.support.RemoteInvocation;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.UUID;

/**
 * //TODO - Class JavaDoc!
 *
 * @author Les Hazlewood
 * @since Mar 28, 2009 4:14:01 PM
 */
public class SecureRemoteInvocationFactoryTest {

    @Before
    public void setup() {
        ThreadContext.clear();
    }

    protected void bind( Subject subject ) {
        ThreadContext.bind(subject);
    }

    @After
    public void tearDown() {
        ThreadContext.clear();
    }

    protected Method getMethod(String name, Class clazz) {
        Method[] methods = clazz.getMethods();
        for( Method method : methods ) {
            if ( method.getName().equals(name) ) {
                return method;
            }
        }
        throw new IllegalStateException( "'" + name + "' method should exist." );
    }

    @Test
    public void testSessionManagerProxyStartRemoteInvocation() throws Exception {

        SecureRemoteInvocationFactory factory = new SecureRemoteInvocationFactory();

        MethodInvocation mi = createMock(MethodInvocation.class);
        Method startMethod = getMethod("start", SessionManager.class);
        expect(mi.getMethod()).andReturn(startMethod).anyTimes();
        
        Object[] args = {InetAddress.getLocalHost()};
        expect(mi.getArguments()).andReturn(args).anyTimes();

        replay(mi);

        RemoteInvocation ri = factory.createRemoteInvocation(mi);

        verify(mi);

        assertNull(ri.getAttribute(SecureRemoteInvocationFactory.SESSION_ID_KEY));
    }

    @Test
    public void testSessionManagerProxyNonStartRemoteInvocation() throws Exception {

        SecureRemoteInvocationFactory factory = new SecureRemoteInvocationFactory();

        MethodInvocation mi = createMock(MethodInvocation.class);
        Method method = getMethod("isValid", SessionManager.class);
        expect(mi.getMethod()).andReturn(method).anyTimes();

        String dummySessionId = UUID.randomUUID().toString();
        Object[] args = {dummySessionId};
        expect(mi.getArguments()).andReturn(args).anyTimes();

        replay(mi);

        RemoteInvocation ri = factory.createRemoteInvocation(mi);

        verify(mi);

        assertEquals(ri.getAttribute(SecureRemoteInvocationFactory.SESSION_ID_KEY), dummySessionId);
    }

    /*@Test
    public void testNonSessionManagerCall() throws Exception {

        SecureRemoteInvocationFactory factory = new SecureRemoteInvocationFactory();

        MethodInvocation mi = createMock(MethodInvocation.class);
        Method method = getMethod("login", SecurityManager.class);
        expect(mi.getMethod()).andReturn(method).anyTimes();
    }*/

}
