package org.jsecurity.samples.spring;

import org.jsecurity.authz.annotation.RolesRequired;

/**
 * Business manager interface used for sample application.
 */
public interface SampleManager {

    String getValue();

    void setValue(String newValue);

    @RolesRequired( "role1" )
    void secureMethod1();

    @RolesRequired( "role2" )
    void secureMethod2();
}
