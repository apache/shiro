package org.apache.shiro.subject.support;

import org.apache.shiro.subject.Subject;

import java.util.concurrent.Callable;

/**
 * @since 1.0
 */
public class SubjectCallable<V> extends ThreadedExecutionSupport implements Callable<V> {

    private final Callable<V> callable;

    public SubjectCallable(Subject subject, Callable<V> delegate) {
        super(subject);
        if (delegate == null) {
            throw new IllegalArgumentException("Callable delegate instance cannot be null.");
        }
        this.callable = delegate;
    }

    public V call() throws Exception {
        try {
            bindThreadState();
            return doCall(this.callable);
        } finally {
            restoreThreadState();
        }
    }

    protected V doCall(Callable<V> target) throws Exception {
        return target.call();
    }
}
