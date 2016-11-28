package org.apache.shiro.samples.cdi

import org.apache.deltaspike.testcontrol.api.junit.CdiTestRunner
import org.junit.Test
import org.junit.runner.RunWith

import javax.inject.Inject

/**
 * Simple Test for {@link CdiQuickStart}.
 */
@RunWith(CdiTestRunner)
class CdiQuickStartIT {

    @Inject
    CdiQuickStart cdiQuickStart;

    @Test
    void runQuickStart() {

        println("WTF")

        cdiQuickStart.runMe()
    }
}
