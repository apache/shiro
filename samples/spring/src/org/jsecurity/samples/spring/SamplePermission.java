package org.jsecurity.samples.spring;

import org.jsecurity.authz.support.SimpleNamedPermission;

/**
 * Sample permission used in Spring sample app.
 */
public class SamplePermission extends SimpleNamedPermission {

    public SamplePermission(String name) {
        super(name);
    }
}
