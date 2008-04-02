package org.jsecurity.authc;

import org.jsecurity.ExceptionTest;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 29, 2008
 * Time: 1:33:05 PM
 * To change this template use File | Settings | File Templates.
 */
public class ExpiredCredentialsExceptionTest extends ExceptionTest {

    protected Class getExceptionClass() {
        return ExpiredCredentialsException.class;
    }
}
