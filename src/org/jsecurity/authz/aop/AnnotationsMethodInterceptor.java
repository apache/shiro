package org.jsecurity.authz.aop;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.support.AnnotationMethodAuthorizer;
import org.jsecurity.authz.support.PermissionAnnotationMethodAuthorizer;
import org.jsecurity.authz.support.RoleAnnotationMethodAuthorizer;

import java.util.ArrayList;
import java.util.Collection;

/**
 * An <tt>AnnotationsMethodInterceptor</tt> is a MethodInterceptor that asserts a given method is allowed
 * to execute based on one or more configured <tt>AnnotationMethodAuthorizer</tt>s.
 *
 * <p>That is, this method interceptor allows annotations on that method to be processed before the method
 * executes, and if any of the <tt>AnnotationMethodAuthorizer</tt> indicate that the method should not be
 * executed, an <tt>AuthorizationException</tt> will be thrown, otherwise the method will be invoked as expected.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class AnnotationsMethodInterceptor extends MethodInterceptorSupport {

    protected Collection<AnnotationMethodAuthorizer> methodAuthorizers = null;

    public void init() {
        super.init();
        if ( methodAuthorizers == null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "No methodAuthorizers configured.  " +
                          "Enabling default Role and Permission annotation support..." );
            }
            methodAuthorizers = new ArrayList<AnnotationMethodAuthorizer>(2);
            methodAuthorizers.add( new RoleAnnotationMethodAuthorizer( getSecurityManager() ) );
            methodAuthorizers.add( new PermissionAnnotationMethodAuthorizer( getSecurityManager() ) );
        }

    }

    public Collection<AnnotationMethodAuthorizer> getMethodAuthorizers() {
        return methodAuthorizers;
    }

    public void setMethodAuthorizers(Collection<AnnotationMethodAuthorizer> methodAuthorizers) {
        this.methodAuthorizers = methodAuthorizers;
    }

    protected void assertAuthorized(MethodInvocation methodInvocation) throws AuthorizationException {
        //default implementation just ensures no deny votes are cast:
        Collection<AnnotationMethodAuthorizer> amas = getMethodAuthorizers();
        if ( amas != null && !amas.isEmpty() ) {
            for( AnnotationMethodAuthorizer ama : amas ) {
                ama.assertAuthorized( methodInvocation );
            }
        }
    }
}
