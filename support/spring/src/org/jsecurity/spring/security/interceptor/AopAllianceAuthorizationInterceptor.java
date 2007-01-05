package org.jsecurity.spring.security.interceptor;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.aop.AbstractAuthorizationInterceptor;

import java.lang.reflect.Method;

/**
 * @since 0.2
 * @author Les Hazlewood
 */
public class AopAllianceAuthorizationInterceptor
        extends AbstractAuthorizationInterceptor implements MethodInterceptor {

    protected AuthorizedAction createAuthzAction(final Object aopAllianceMethodInvocation) {
        final MethodInvocation mi = (MethodInvocation) aopAllianceMethodInvocation;

        org.jsecurity.authz.method.MethodInvocation jsecurityMI =
                new org.jsecurity.authz.method.MethodInvocation() {
                    public Method getMethod() {
                        return mi.getMethod();
                    }

                    public Object[] getArguments() {
                        return mi.getArguments();
                    }

                    public String toString() {
                        return "Method invocation [" + mi.getMethod() + "]";
                    }
                };

        return jsecurityMI;
    }

    protected Object continueInvocation( Object aopAllianceMethodInvocation ) throws Throwable {
        MethodInvocation mi = (MethodInvocation)aopAllianceMethodInvocation;
        return mi.proceed();
    }

    public Object invoke( MethodInvocation methodInvocation ) throws Throwable {
        return super.invoke(methodInvocation);
    }
}
