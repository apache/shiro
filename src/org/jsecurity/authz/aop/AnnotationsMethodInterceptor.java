package org.jsecurity.authz.aop;

import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.AuthorizationException;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Jan 6, 2008
 * Time: 7:17:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class AnnotationsMethodInterceptor extends MethodInterceptorSupport {

    protected MethodInvocation createMethodInvocation(Object implSpecificMethodInvocation) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    protected void assertAuthorized(MethodInvocation methodInvocation) throws AuthorizationException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    protected Object continueInvocation(Object implSpecificMethodInvocation) throws Throwable {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
