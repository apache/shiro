package org.apache.shiro.config;

import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;

/**
 * @since 1.2.2
 */
public class InitializableBean implements Initializable {

    private volatile boolean initialized = false;

    public void init() throws ShiroException {
        initialized = true;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
