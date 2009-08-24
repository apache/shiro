package org.apache.shiro.mgt;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectBuilder;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.util.ThreadState;
import org.junit.After;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Aug 24, 2009
 * Time: 5:20:35 PM
 * To change this template use File | Settings | File Templates.
 */
public abstract class AbstractSecurityManagerTest {

    protected ThreadState threadState;

    @After
    public void tearDown() {
        ThreadContext.clear();
    }

    protected Subject newSubject(SecurityManager securityManager) {
        Subject subject = new SubjectBuilder(securityManager).buildSubject();
        threadState = new SubjectThreadState(subject);
        threadState.bind();
        return subject;
    }
}
