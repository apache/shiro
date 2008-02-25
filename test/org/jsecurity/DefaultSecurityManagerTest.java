package org.jsecurity;

import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class DefaultSecurityManagerTest {

    DefaultSecurityManager sm = null;

    @Before
    public void setup() {
        sm = new DefaultSecurityManager();
    }

    @After
    public void tearDown() {
        sm.destroy();
    }

    @Test
    public void testDefaultConfig() {
        sm.init();
        InetAddress localhost = null;
        try {
            localhost = InetAddress.getLocalHost();
        } catch ( UnknownHostException e ) {
            e.printStackTrace();  
        }
        Subject subject = sm.login( new UsernamePasswordToken( "guest", "guest", localhost ) );
        assert subject.isAuthenticated();
        assert "guest".equals( subject.getPrincipal() );
        assert subject.hasRole( "guest" );
        Session session = subject.getSession();
        subject.logout();
    }
}
