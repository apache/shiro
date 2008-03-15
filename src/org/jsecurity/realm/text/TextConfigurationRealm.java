package org.jsecurity.realm.text;

import org.jsecurity.authz.Permission;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.authz.SimpleRole;
import org.jsecurity.realm.SimpleAccountRealm;
import org.jsecurity.util.PermissionUtils;
import org.jsecurity.util.StringUtils;

import java.text.ParseException;
import java.util.*;

/**
 * <p>a SimpleAccountRealm that enables text-based configuration of the initial User, Role, and Permission objects
 * created at startup.
 *
 * <p>Each User account definition specifies the username, password, and roles for a user.  Each Role definition
 * specifies a name and an optional collection of assigned Permissions.  Users can be assigned Roles, and Roles can be
 * assigned Permissions.  By transitive association, each User 'has' all of their Role's Permissions.</p>
 *
 * <p>User and user-to-role definitinos are specified via the {@link #setUserDefinitions} method and
 * Role-to-permission definitions are specified via the {@link #setRoleDefinitions} method.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class TextConfigurationRealm extends SimpleAccountRealm {

    private String userDefinitions;
    private String roleDefinitions;

    public TextConfigurationRealm() {
    }

    public String getUserDefinitions() {
        return userDefinitions;
    }

    /**
     * <p>Sets a newline (\n) delimited String that defines user-to-password-and-role(s) key/value pairs according
     * to the following format:
     *
     * <p><code><em>username</em> = <em>password</em>, role1, role2,...</code></p>
     *
     * <p>Here are some examples of what these lines might look like:</p>
     *
     * <p><code>root = <em>reallyHardToGuessPassword</em>, administrator<br/>
     * jsmith = <em>jsmithsPassword</em>, manager, engineer, employee<br/>
     * abrown = <em>abrownsPassword</em>, qa, employee<br/>
     * djones = <em>djonesPassword</em>, qa, contractor<br/>
     * guest = <em>guestPassword</em></code></p>
     *
     * @param userDefinitions the user definitions to be parsed and converted to Map.Entry elements
     */
    public void setUserDefinitions(String userDefinitions) {
        this.userDefinitions = userDefinitions;
    }

    public String getRoleDefinitions() {
        return roleDefinitions;
    }

    /**
     * Sets a newline (\n) delimited String that defines role-to-permission definitions.
     *
     * <p>Each line within the string must define a role-to-permission(s) key/value mapping with the
     * equals character signifies the key/value separation, like so:</p>
     *
     * <p><code><em>rolename</em> = <em>permissionDefinition1</em>, <em>permissionDefinition2</em>, ...</code></p>
     *
     * <p>where <em>permissionDefinition</em> is an arbitrary String, but must people will want to use
     * Strings that conform to the {@link org.jsecurity.authz.permission.WildcardPermission WildcardPermission}
     * format for ease of use and flexibility.  Note that if an individual <em>permissionDefnition</em> needs to
     * be internally comma-delimited (e.g. <code>printer:5thFloor:print,info</code>), you will need to surround that
     * definition with double quotes (&quot;) to avoid parsing errors (e.g.
     * <code>&quot;printer:5thFloor:print,info&quot;</code>).
     *
     * <p>Finally, if you have roles that don't require permission associations, don't include them in this
     * definition - just defining the role name in the {@link #setUserDefinitions(String) userDefinitions} is
     * enough to create the role if it does not yet exist.
     *
     * @param roleDefinitions the role definitions to be parsed at initialization
     */
    public void setRoleDefinitions(String roleDefinitions) {
        this.roleDefinitions = roleDefinitions;
    }


    protected void userAndRoleCachesCreated() {
        processDefinitions();
    }

    protected void processDefinitions() {
        try {
            processRoleDefinitions();
            processUserDefinitions();
        } catch (ParseException e) {
            String msg = "Unable to parse user and/or role definitions.";
            throw new IllegalStateException(msg, e);
        }
    }

    protected void processRoleDefinitions() throws ParseException {
        String roleDefinitions = getRoleDefinitions();
        if (roleDefinitions == null) {
            return;
        }
        Map<String, String> roleDefs = toMap( toLines(roleDefinitions) );
        if (roleDefs == null || roleDefs.isEmpty()) {
            return;
        }

        for (String rolename : roleDefs.keySet()) {
            String value = roleDefs.get(rolename);

            SimpleRole role = getRole(rolename);
            if (role == null) {
                role = new SimpleRole(rolename);
                add(role);
            }

            Set<Permission> permissions = PermissionUtils.resolveDelimitedPermissions(value, getPermissionResolver());
            role.setPermissions(permissions);
        }
    }

    protected void processUserDefinitions() throws ParseException {

        String userDefinitions = getUserDefinitions();
        if ( userDefinitions == null ) {
            return;
        }

        Map<String, String> userDefs = toMap( toLines(userDefinitions));
        if (userDefs == null || userDefs.isEmpty()) {
            return;
        }

        for (String username : userDefs.keySet()) {

            String value = userDefs.get(username);

            String[] passwordAndRolesArray = StringUtils.split(value);

            String password = passwordAndRolesArray[0];
            SimpleAuthorizingAccount user = getUser(username);
            if (user == null) {
                user = new SimpleAuthorizingAccount(username, password);
                add(user);
            }
            user.setCredentials(password);

            if (passwordAndRolesArray.length > 1) {
                for( int i = 1; i < passwordAndRolesArray.length; i++ ) {
                    String rolename = passwordAndRolesArray[i];
                    SimpleRole role = getRole(rolename);
                    if (role == null) {
                        role = new SimpleRole(rolename);
                        add(role);
                    }
                    user.add(role);
                }
            } else {
                user.setRoles(null);
            }
        }
    }

    protected static Set<String> toLines( String s ) {
        LinkedHashSet<String> set = new LinkedHashSet<String>();
        Scanner scanner = new Scanner(s);
        while (scanner.hasNextLine()) {
            set.add(scanner.nextLine());
        }
        return set;
    }

    protected static Map<String, String> toMap(Collection<String> keyValuePairs) throws ParseException {
        if (keyValuePairs == null || keyValuePairs.isEmpty()) {
            return null;
        }

        Map<String, String> pairs = new HashMap<String, String>();
        for (String pairString : keyValuePairs) {
            String[] pair = StringUtils.splitKeyValue(pairString);
            pairs.put(pair[0].trim(), pair[1].trim());
        }

        return pairs;
    }

    public void onLogout(Object accountPrincipal) {
        //override parent method of removing user from cache
        //we don't want that to happen on cache-only realm since that would permanently
        //remove the user from the realm.
    }
}
