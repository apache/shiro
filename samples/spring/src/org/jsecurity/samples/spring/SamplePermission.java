package org.jsecurity.samples.spring;

import org.jsecurity.authz.support.AbstractPermission;

/**
 * Sample permission used in Spring sample app.
 */
public class SamplePermission extends AbstractPermission {

    public SamplePermission(String name) {
        super(name);
    }
}
