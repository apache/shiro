package org.ops4j.pax.shiro.cdi;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import javax.inject.Inject;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class ShiroFactoryTest extends AbstractCdiTest {
    
    @Inject
    private Subject subject;
    
    @Inject
    private SecurityManager securityManager;
    
    @Inject
    private Session session;
    
    @Test
    public void checkSubjectIsManaged() {
        assertNotNull(subject);
        assertFalse(subject.isAuthenticated());
    }

    @Test
    public void checkSecurityManagerIsManaged() {
        assertNotNull(securityManager);
    }

    @Test
    public void checkSessionIsManaged() {
        assertNotNull(session);
    }
}
