package org.apache.shiro.util;

/**
 * A {@code ThreadState} instance manages any state that might need to be bound and/or restored during a thread's
 * execution.
 *
 * @since 1.0
 */
public interface ThreadState {

    /**
     * Binds any state that should be made accessible during a thread's execution.
     */
    void bind();

    /**
     * Restores a thread to its state before bind {@link #bind bind} was invoked.
     */
    void restore();

    /**
     * Clears a thread's state modifications entirely.
     */
    void clear();

}
