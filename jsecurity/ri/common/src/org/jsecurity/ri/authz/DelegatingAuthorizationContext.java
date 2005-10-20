package org.jsecurity.ri.authz;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizationException;

import java.io.Serializable;
import java.security.Principal;
import java.security.Permission;
import java.util.List;
import java.util.Collection;

/**
 * Simple implementation of the <tt>AuthorizationContext</tt> interface that delegates all
 * method calls to an underlying {@link Realm Realm} instance for security checks.  It is
 * essentially a <tt>Realm</tt> proxy.
 *
 * <p>This implementation does not maintain state such as roles and permissions (only a subject
 * identifier, such as a  user primary key or username) for better performance in a stateless
 * architecture.  It instead asks the underlying <tt>Realm</tt> every time to perform
 * the authorization check.
 *
 * <p>A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying <tt>Realm</tt> instance.  If caching of authorization
 * context data is desiered (to eliminate EIS round trips and therefore improve database
 * performance), it is considered much more
 * elegant to let the underlying Realm implementation manage caching, not this class.  A Realm is
 * considered a business-tier component, where caching strategies are better managed.
 *
 * <p>Applications from large and clustered to simple and vm local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 *
 * @author Les Hazlewood
 */
public class DelegatingAuthorizationContext implements AuthorizationContext {

    private Serializable subjectIdentifier;

    private Realm realm;

    public DelegatingAuthorizationContext() {}

    public DelegatingAuthorizationContext( Serializable subjectIdentifier, Realm realm ) {
        setSubjectIdentifier( subjectIdentifier );
        setRealm( realm );
    }

    public Serializable getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public void setSubjectIdentifier( Serializable subjectIdentifier ) {
        this.subjectIdentifier = subjectIdentifier;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm( Realm realm ) {
        this.realm = realm;
    }

    public Principal getPrincipal() {
        throw new IllegalStateException( "Not yet implemented" );
    }

    public boolean hasRole( String roleIdentifier ) {
        return realm.hasRole( subjectIdentifier, roleIdentifier );
    }

    public boolean[] hasRoles( List<String> roleIdentifiers ) {
        return realm.hasRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean hasAllRoles( Collection<String> roleIdentifiers ) {
        return realm.hasAllRoles( subjectIdentifier, roleIdentifiers );
    }

    public boolean hasPermission( Permission permission ) {
        return realm.isPermitted( subjectIdentifier, permission );
    }

    public boolean[] hasPermissions( List<Permission> permissions ) {
        return realm.isPermitted( subjectIdentifier, permissions );
    }

    public boolean hasAllPermissions( Collection<Permission> permissions ) {
        return realm.isPermittedAll( subjectIdentifier, permissions );
    }

    public void checkPermission( Permission permission ) throws AuthorizationException {
        realm.checkPermission( subjectIdentifier, permission );
    }

    public void checkPermissions( Collection<Permission> permissions )
        throws AuthorizationException {
        realm.checkPermissions( subjectIdentifier, permissions );
    }

}
