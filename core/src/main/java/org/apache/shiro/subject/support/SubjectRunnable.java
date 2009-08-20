package org.apache.shiro.subject.support;

import org.apache.shiro.subject.Subject;

/**
 * @since 1.0
 */
public class SubjectRunnable extends ThreadedExecutionSupport implements Runnable {

    private final Runnable runnable;

    public SubjectRunnable(Subject subject, Runnable delegate) {
        super(subject);
        if (delegate == null) {
            throw new IllegalArgumentException("Runnable argument cannot be null.");
        }
        this.runnable = delegate;
    }

    public void run() {
        try {
            bindThreadState();
            doRun();
        } finally {
            restoreThreadState();
        }
    }

    protected void doRun() {
        this.runnable.run();
    }
}
