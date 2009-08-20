package org.apache.shiro.subject.support;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.DelegatingSubject;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * @since 0.1
 */
public class ThreadedExecutionSupport {

    private final Subject originalSubject;
    private final InetAddress originalInetAddress;
    private final Serializable originalSessionId;
    private final transient SecurityManager originalSecurityManager;

    /*protected static Subject assertThreadSubject() {
        Subject subject = ThreadContext.getSubject();
        if (subject == null) {
            String msg = "Unable to acquire Subject instance from ThreadLocal via " +
                    ThreadContext.class.getName() + ".getSubject().  This is most likely due to a " +
                    "configuration error - there should always be a Subject present when using the " +
                    "single argument " + SubjectCallable.class.getSimpleName() + " constructor.";
            throw new IllegalStateException(msg);
        }
        return subject;
    }

    public SubjectCallable(Callable<V> delegate) {
        this(delegate, assertThreadSubject());
    }*/

    public ThreadedExecutionSupport(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.originalSubject = subject;

        //TODO - not an interface call (yuck)
        if (this.originalSubject instanceof DelegatingSubject) {
            this.originalSecurityManager = ((DelegatingSubject) this.originalSubject).getSecurityManager();
        } else {
            this.originalSecurityManager = ThreadContext.getSecurityManager();
        }

        Session session = this.originalSubject.getSession(false);

        InetAddress inet = null;
        if (session != null) {
            inet = session.getHostAddress();
        }
        if (inet == null) {
            inet = ThreadContext.getInetAddress();
        }
        this.originalInetAddress = inet;

        if (session != null) {
            this.originalSessionId = session.getId();
        } else {
            this.originalSessionId = ThreadContext.getSessionId();
        }
    }

    public void bindThreadState() {
        ThreadContext.bind(this.originalSecurityManager);
        ThreadContext.bind(this.originalSubject);
        ThreadContext.bind(this.originalInetAddress);
        ThreadContext.bindSessionId(this.originalSessionId);
    }

    public void restoreThreadState() {
        if (originalSubject == null) {
            ThreadContext.unbindSubject();
        } else {
            ThreadContext.bind(originalSubject);
        }
        if (originalInetAddress == null) {
            ThreadContext.unbindInetAddress();
        } else {
            ThreadContext.bind(originalInetAddress);
        }
        if (originalSecurityManager == null) {
            ThreadContext.unbindSecurityManager();
        } else {
            ThreadContext.bind(originalSecurityManager);
        }
        if (originalSessionId == null) {
            ThreadContext.unbindSessionId();
        } else {
            ThreadContext.bindSessionId(originalSessionId);
        }
    }

    public void clearAllThreadState() {
        ThreadContext.clear();
    }
}
