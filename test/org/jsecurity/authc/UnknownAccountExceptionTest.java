package org.jsecurity.authc;

import org.jsecurity.ExceptionTest;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 30, 2008
 * Time: 2:55:33 PM
 * To change this template use File | Settings | File Templates.
 */
public class UnknownAccountExceptionTest extends ExceptionTest {

    protected Class getExceptionClass() {
        return UnknownAccountException.class;
    }
}
