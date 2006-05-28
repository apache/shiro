package org.jsecurity.ri.jboss.aop;

import org.jboss.aop.advice.Interceptor;
import org.jboss.aop.joinpoint.Invocation;
import org.jboss.aop.joinpoint.MethodInvocation;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.ri.authz.aop.AbstractAuthorizationInterceptor;

import java.lang.reflect.Method;

/**
 * @since 0.2
 * @author Les Hazlewood
 */
public class JBossAopAuthorizationInterceptor
        extends AbstractAuthorizationInterceptor implements Interceptor {

    private static final String NAME = "JSecurity JBossAopAuthorizationInterceptor";

    public JBossAopAuthorizationInterceptor(){}

    public JBossAopAuthorizationInterceptor( Authorizer authorizer ) {
        setAuthorizer( authorizer );
    }

    public String getName() {
        return NAME;
    }

    protected AuthorizedAction createAuthzAction( Object jbossAopInvocation ) {
        final MethodInvocation mi = (MethodInvocation)jbossAopInvocation;

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

    protected Object continueInvocation( Object jbossAopInvocation ) throws Throwable {
        Invocation invocation = (Invocation)jbossAopInvocation;
        return invocation.invokeNext();
    }

    public Object invoke( final Invocation invocation ) throws Throwable {
        return super.invoke( invocation );
    }

}
