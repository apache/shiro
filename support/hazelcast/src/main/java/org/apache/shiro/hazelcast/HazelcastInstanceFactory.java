package org.apache.shiro.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.Initializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for providing {@link HazelcastInstance}s.  Subclasses create either an embedded Hazelcast server
 * node that will be a member of the Hazelcast cluster or a lightweight client that is not a server member, but only
 * interacts with server members.
 *
 * @see ClientHazelcastInstanceFactory
 * @see EmbeddedHazelcastInstanceFactory
 */
public abstract class HazelcastInstanceFactory implements Factory<HazelcastInstance>, Initializable, Destroyable {

    private static final Logger log = LoggerFactory.getLogger(ClientHazelcastInstanceFactory.class);

    private HazelcastInstance instance;

    public synchronized HazelcastInstance getInstance() {
        if (this.instance == null) {
            this.instance = createInstance();
        }
        return this.instance;
    }

    protected abstract HazelcastInstance createInstance();

    public void init() throws ShiroException {
        getInstance(); //will auto-create the instance as necessary.
    }

    public void destroy() throws Exception {
        if (this.instance == null) return;

        try {
            this.instance.getLifecycleService().shutdown();
        } catch (Throwable t) {
            if (log.isWarnEnabled()) {
                log.warn("Unable to cleanly shutdown implicitly created HazelcastInstance.  " +
                        "Ignoring (shutting down)...", t);
            }
        } finally {
            this.instance = null;
        }
    }
}
