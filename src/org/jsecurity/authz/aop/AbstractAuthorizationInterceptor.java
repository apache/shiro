package org.jsecurity.authz.aop;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.ThreadLocalSecurityContext;

/**
 * This class is an abstraction of AOP method interceptor behavior specific to JSecurity that
 * leaves AOP implementation specifics to be handled by subclass implementations.  Shared behavior
 * is defined in this class.
 *
 * <p>Different frameworks represent Method Invocations (MI) in different ways, so this class
 * aggregates as much JSecurity interceptor behavior as possible, leaving framework MI details to
 * subclasses via template methods.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AbstractAuthorizationInterceptor {

    protected transient final Log log = LogFactory.getLog( getClass() );

    private Authorizer authorizer;

    private SecurityContext securityContext = new ThreadLocalSecurityContext();

    public AbstractAuthorizationInterceptor(){}

    public void setAuthorizer( Authorizer authorizer ) {
        this.authorizer = authorizer;
    }

    /**
     * Sets the SecurityContext that will be used when performing an authorization check.
     *
     * <p>The default instance internally is an instance of {@link org.jsecurity.context.support.ThreadLocalSecurityContext},
     * which should be used in all server environments and not overridden (unless you really know
     * what you're doing).
     *
     * <p>This method is primarily presented as a
     * convenient overriding mechanism to allow explicitly setting the <tt>SecurityContext</tt> in
     * standalone application environments, such as Swing or command-line applications.
     *
     * @param securityContext the SecurityContext to use when this interceptor performs an
     * authorization check.
     */
    public void setSecurityContext( SecurityContext securityContext ) {
        this.securityContext = securityContext;
    }

    public void init() throws Exception {
        if ( this.authorizer == null ) {
            String msg = "authorizer property must be set";
            throw new IllegalStateException( msg );
        }
    }

    protected Object invoke( final Object implSpecificMethodInvocation ) throws Throwable {

        SecurityContext secCtx = this.securityContext;

        if ( secCtx != null ) {
            AuthorizedAction action = createAuthzAction( implSpecificMethodInvocation );
            //will throw an exception if not authorized to execute the action:
            this.authorizer.checkAuthorization(secCtx, action );
        } else {
            String msg = "No SecurityContext available " +
                         "(User not authenticated?).  Authorization failed.";
            throw new UnauthorizedException( msg );
        }

        //secCtx was found, and it determined the AOP invocation chain should proceed:
        return continueInvocation( implSpecificMethodInvocation );
    }

    protected abstract AuthorizedAction createAuthzAction( Object implSpecificMethodInvocation );

    protected abstract Object continueInvocation( Object implSpecificMethodInvocation ) throws Throwable;
}
