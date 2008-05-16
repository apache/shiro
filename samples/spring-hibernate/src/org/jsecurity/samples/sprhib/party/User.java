/*
 * Copyright 2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.samples.sprhib.party;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.samples.sprhib.security.Role;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;

import java.text.DateFormat;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Simple class that represents any User domain entity in any application.  It extends the {@link Person Person} class
 * to show a non-trivial class hierarchy, since such hierarchies exist in most Hibernate applications in one form
 * or another.  Naturally you could ignore the parent class in your application, but it does represent a clean
 * OO way of modeling things.
 *
 * <p>This class implements the {@link AuthorizingAccount AuthorizingAccount} interface for dead-simple integration
 * with JSecurity - this allows you to use your User objects directly inside of
 * {@link org.jsecurity.realm.Realm Realm} implementations, significantly reducing the implementation effort.</p>
 *
 * <p>Because this class performs its own Realm and Permission checks, and these can happen frequently enough in a
 * production application, it is highly recommended that the internal User {@link #getRoles roles} collection be cached
 * in a 2nd-level cache when using JPA and/or Hibernate.  The hibernate xml configuration for this sample application
 * does in fact do this for your reference (see User.hbm.xml - the 'roles' declaration).</p>
 *
 * <p>If you ever decide not to use JSecurity, the only domain change should be to remove the
 * <code>AuthorizingAccount</code> interface declaration and its methods.</p>
 *
 * @author Les Hazlewood
 */
public class User extends Person implements AuthorizingAccount {

    /**
     * Requires 6 or more alphanumeric and/or punctuation characters.
     */
    public static final Pattern VALID_PASSWORD_PATTERN = Pattern.compile( "[\\p{Alnum}\\p{Punct}]{6,255}" );

    public static final Pattern VALID_USERNAME_PATTERN = Pattern.compile( "[\\p{Alnum}_-]{1,255}" );

    public static final String ROOT_USER_USERNAME = "root";

    private String username;
    private String password;
    private String passwordResetKey = null; //UUID generated when they ask to reset the password
    private Date passwordResetKeyTimestamp = null; //when they asked to reset the password
    private Date lastLoginTimestamp; //can be null if never logged in
    private Date lockTimestamp; //date the account was locked, null means unlocked (default behavior)
    private boolean sessionTimeoutEnabled = true; //per-user session configuration

    private Set<Role> roles;

    public User() {
    }


    /**
     * Returns the username associated with this user account;
     *
     * @return the username associated with this user account;
     */
    public String getUsername() {
        return username;
    }

    public void setUsername( String username ) {
        this.username = username;
    }

    /**
     * Returns the password for this user.
     *
     * @return this user's password
     */
    public String getPassword() {
        return password;
    }

    public void setPassword( String password ) {
        this.password = password;
    }

    /**
     * If the user forgets their password, this key is set first.  If they then request to reset their password, they
     * must submit this key for the reset request to be valid.  Otherwise, the password reset is timed out after a
     * certain amount of time after {@link #getPasswordResetKeyTimestamp() passwordResetKeyTimestamp} 
     * @return
     */
    public String getPasswordResetKey() {
        return passwordResetKey;
    }

    public void setPasswordResetKey( String passwordResetKey ) {
        this.passwordResetKey = passwordResetKey;
    }

    public Date getPasswordResetKeyTimestamp() {
        return passwordResetKeyTimestamp;
    }

    public void setPasswordResetKeyTimestamp( Date passwordResetKeyTimestamp ) {
        this.passwordResetKeyTimestamp = passwordResetKeyTimestamp;
    }

    /**
     * Returns the timestamp this User last logged in successfully to the application, or
     * <tt>null</tt> if the user has never logged in.
     *
     * @return the timestamp this User last logged in successfully to the application, or
     *         <tt>null</tt> if the user has never logged in.
     */
    public Date getLastLoginTimestamp() {
        return lastLoginTimestamp;
    }

    /**
     * Sets the timestamp this User last logged in successfully to the application.
     *
     * @param lastLoginTimestamp the timestamp this User last logged in successfully to the
     *                           application.
     */
    public void setLastLoginTimestamp( Date lastLoginTimestamp ) {
        this.lastLoginTimestamp = lastLoginTimestamp;
    }

    /**
     * Returns the time when this account was locked, either due to too many login attempts, an
     * explicit lock-out by an administrator, or because of some other security reason. <p>This
     * method returns <tt>null</tt> if the account is not locked and is considered to be in good
     * standing</p>
     *
     * @return the time when this account was locked, or <tt>null</tt> if this account is not locked
     *         and is considered to be in good standing.
     */
    public Date getLockTimestamp() {
        return lockTimestamp;
    }

    public void setLockTimestamp( Date lockTimestamp ) {
        this.lockTimestamp = lockTimestamp;
    }

    /**
     * Returns whether or not this particular user account can expire due to inactivity. <p>Defaults
     * to <tt>true</tt> as almost all user accounts should expire due to inactivity.
     *
     * @return <tt>true</tt> if this user's sessions can timeout due to inactivity, <tt>false</tt>
     *         otherwise.
     */
    public boolean isSessionTimeoutEnabled() {
        return sessionTimeoutEnabled;
    }

    public void setSessionTimeoutEnabled( boolean sessionTimeoutEnabled ) {
        this.sessionTimeoutEnabled = sessionTimeoutEnabled;
    }

    /**
     * Returns whether or not this user account is locked, thereby preventing further log-ins.
     *
     * @return <tt>true</tt> if this user account is locked and will not be allowed to log-in,
     *         <tt>false</tt>
     */
    public boolean isLocked() {
        return getLockTimestamp() != null;
    }

    /**
     * Convenience method for updating the state to locked.
     *
     * @see #getLockTimestamp()
     * @param locked whether or not this user account will be locked.
     */
    public void setLocked( boolean locked ) {
        if ( locked ) {
            if ( getLockTimestamp() == null ) {
                setLockTimestamp( new Date() );
            }
        } else {
            setLockTimestamp( null );
        }
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles( Set<Role> roles ) {
        this.roles = roles;
    }

    public Role getRole( String name ) {
        Collection<Role> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( Role role : roles ) {
                if ( role.getName().equals(name) ) {
                    return role;
                }
            }
        }
        return null;
    }

    /**
     * Adds a Role to this user's collection of {@link #getRoles() roles}.
     * <p/>
     * <p>If the existing roles collection is <tt>null</tt>, a new collection will be created and
     * assigned to this User and then the Role will be added.
     *
     * @param r the Role to add/associate with this User
     */
    public void add( Role r ) {
        Set<Role> roles = getRoles();
        if ( roles == null ) {
            roles = new LinkedHashSet<Role>();
            setRoles( roles );
        }
        roles.add( r );
    }

    public boolean removeRole( Role r ) {
        Set<Role> roles = getRoles();
        return roles != null && roles.remove(r);
    }

    protected String getPrivateRoleName( PrincipalCollection principals ) {
        return getClass().getName() + "_PRIVATE_ROLE_" + PrincipalCollection.class.getName();
    }

    protected Role createPrivateRole( PrincipalCollection principals ) {
        String privateRoleName = getPrivateRoleName(principals);
        return new Role(privateRoleName, this);
    }

    public Set<Permission> getPermissions() {
        Set<Permission> permissions = new HashSet<Permission>();
        for (Role role : roles) {
            permissions.addAll(role.getPermissions());
        }
        return permissions;
    }

    public Set<String> getRolenames() {
        Set<String> rolenames = new HashSet<String>();
        for (Role role : roles) {
            rolenames.add(role.getName());
        }
        return rolenames;
    }

    public void addRole( String roleName ) {
        Role existing = getRole(roleName);
        if ( existing == null ) {
            Role role = new Role(roleName);
            add(role);
        }
    }

    public void addRoles( Set<String> roleNames ) {
        if ( roleNames != null && !roleNames.isEmpty() ) {
            for( String name : roleNames ) {
                addRole( name );
            }
        }
    }

    public void addAll(Collection<Role> roles) {
        if (roles != null && !roles.isEmpty()) {
            Set<Role> existingRoles = getRoles();
            if (existingRoles == null) {
                existingRoles = new LinkedHashSet<Role>(roles.size());
                setRoles(existingRoles);
            }
            existingRoles.addAll(roles);
        }
    }


    public static boolean isValidPassword( String password ) {
        return password != null && VALID_PASSWORD_PATTERN.matcher( password ).matches();
    }

    public static boolean isValidUsername( String username ) {
        return username != null && VALID_USERNAME_PATTERN.matcher( username ).matches();
    }


    public StringBuffer toStringBuffer() {
        StringBuffer sb = super.toStringBuffer();
        sb.append( ",username=" ).append( getUsername() );
        sb.append( ",password=<protected>" );
        DateFormat df = DateFormat.getInstance();
        Date ts = getLastLoginTimestamp();
        if ( ts != null ) {
            sb.append( ",lastLoginTimestamp=" ).append( df.format( ts ) );
        }
        ts = getLockTimestamp();
        if ( ts != null ) {
            sb.append( ",lockTimestamp=" ).append( df.format( ts ) );
        }
        sb.append( ",sessionTimeoutEnabled=" ).append( isSessionTimeoutEnabled() );

        return sb;
    }

    public boolean onEquals( Object o ) {
        if ( o instanceof User ) {
            User u = (User) o;
            return getUsername().equals( u.getUsername() );
        }

        return false;
    }

    public int hashCode() {
        return getUsername().hashCode();
    }

    @Override
    @SuppressWarnings( {"CloneDoesntDeclareCloneNotSupportedException"} )
    public Object clone() {
        User clone = (User) super.clone();
        clone.setUsername( getUsername() );
        clone.setPassword( getPassword() );
        clone.setPasswordResetKey( getPasswordResetKey() );
        clone.setPasswordResetKeyTimestamp( getPasswordResetKeyTimestamp() );
        clone.setLastLoginTimestamp( getLastLoginTimestamp() );
        clone.setLockTimestamp( getLockTimestamp() );
        clone.setSessionTimeoutEnabled( isSessionTimeoutEnabled() );
        return clone;
    }

    public static void main( String[] args ) {
        String username = "s-ls";
        if ( !isValidUsername( username ) ) {
            System.out.println( "Not a valid username!" );
        } else {
            System.out.println( "Valid username." );
        }
    }

    /* ===========
       JSecurity AuthorizingAccount implementations below here.
       =========== */
    public PrincipalCollection getPrincipals() {
        //The realm name must match the name of the configured realm.
        return new SimplePrincipalCollection("DefaultRealm", getId() );
    }

    public Object getCredentials() {
        return getPassword();
    }

    public boolean isCredentialsExpired() {
        //if applications wanted to expire passwords after a certain amount of time, this method would calculate
        //true or false based on the current time and a passwordLastUpdateTimestamp;

        //this sample app doesn't use this feature, so just return false always:
        return false;
    }



    public boolean hasRole(String roleName) {
        return getRole(roleName) != null;
    }

    public boolean isPermitted( Permission p ) {
        Set<Role> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for ( Role role : roles ) {
                if ( role.isPermitted( p ) ) {
                    if ( log.isTraceEnabled() ) {
                        String msg = "Permission implies permission argument.  User [" +
                            getUsername() + "] has permission";
                        log.trace( msg );
                    }
                    return true;
                }
            }

        }

        if ( log.isTraceEnabled() ) {
            log.trace( "No assigned permissions implies the permission argument.  User [" +
                getUsername() + "] doesn't have the specified permission" );
        }

        return false;
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] result;
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            int size = roleIdentifiers.size();
            result = new boolean[size];
            int i = 0;
            for (String roleName : roleIdentifiers) {
                result[i++] = hasRole(roleName);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            for (String roleName : roleIdentifiers) {
                if (!hasRole(roleName)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        boolean[] result;
        if (permissions != null && !permissions.isEmpty()) {
            int size = permissions.size();
            result = new boolean[size];
            int i = 0;
            for (Permission p : permissions) {
                result[i++] = isPermitted(p);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                if (!isPermitted(p)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        if (!isPermitted(permission)) {
            String msg = "User is not permitted [" + permission + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                checkPermission(p);
            }
        }
    }

    public void checkRole(String role) {
        if (!hasRole(role)) {
            String msg = "User does not have role [" + role + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkRoles(Collection<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            for (String roleName : roles) {
                checkRole(roleName);
            }
        }
    }


}


