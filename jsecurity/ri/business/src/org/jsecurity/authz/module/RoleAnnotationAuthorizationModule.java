package org.jsecurity.authz.module;

import org.jsecurity.authz.module.AuthorizationVote;
import org.jsecurity.authz.module.AnnotationAuthorizationModule;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.method.MethodInvocation;
import org.jsecurity.authz.annotation.HasRole;

import java.lang.reflect.Method;

/**
 * AuthorizationModule that votes on authorization based on any
 * {@link org.jsecurity.authz.annotation.HasRole HasRole} annotation found on the method
 * being executed.
 *
 * @author Les Hazlewood
 */
public class RoleAnnotationAuthorizationModule extends AnnotationAuthorizationModule {

    public RoleAnnotationAuthorizationModule() {
        setAnnotationClass( HasRole.class );
    }

    public AuthorizationVote isAuthorized( AuthorizationContext context, AuthorizedAction action ) {

        MethodInvocation mi = (MethodInvocation)action;

        if ( mi != null ) {

            Method m = mi.getMethod();
            if ( m == null ) {
                String msg = MethodInvocation.class.getName() + " parameter incorrectly " +
                             "constructed.  getMethod() returned null";
                throw new NullPointerException( msg );
            }

            HasRole hrAnnotation = m.getAnnotation( HasRole.class );
            if ( hrAnnotation != null ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "Found role annotation for role [" + hrAnnotation.value() + "]" );
                }
                if ( context.hasRole( hrAnnotation.value() ) ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "Authorization context has role [" +
                                   hrAnnotation.value() + "]. Returning grant vote.");
                    }
                    return AuthorizationVote.grant;
                } else {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "AuthorizationContext does not have role [" +
                                   hrAnnotation.value() + "].  Returning deny vote.");
                    }
                    return AuthorizationVote.deny;
                }

            } else {
                if ( log.isInfoEnabled() ) {
                    log.info( "No " + HasRole.class.getName() + " annotation declared for " +
                              "method " + m + ".  Returning abstain vote." );
                }
                return AuthorizationVote.abstain;
            }
        } else {
            if ( log.isWarnEnabled() ) {
                log.warn( "AuthorizedAction parameter is null.  Returning abstain vote." );
            }
            return AuthorizationVote.abstain;
        }

    }

}
