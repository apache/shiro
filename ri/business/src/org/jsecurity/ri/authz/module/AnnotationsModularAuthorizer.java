package org.jsecurity.ri.authz.module;

/**
 * A convenience modular authorizer that automatically configures the permission
 * and role authorization modules.  This is simply a convenience mechanism so that
 * less configuration is required.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AnnotationsModularAuthorizer extends ModularAuthorizer {

    public AnnotationsModularAuthorizer() {
        PermissionAnnotationAuthorizationModule permModule = new PermissionAnnotationAuthorizationModule();
        permModule.init();
        addAuthorizationModule( permModule );

        RoleAnnotationAuthorizationModule roleModule = new RoleAnnotationAuthorizationModule();
        roleModule.init();
        addAuthorizationModule( roleModule );
    }
}
