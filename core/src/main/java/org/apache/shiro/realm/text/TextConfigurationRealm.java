/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.text;

import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.util.PermissionUtils;
import org.apache.shiro.lang.util.StringUtils;

import java.text.ParseException;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;


/**
 * A SimpleAccountRealm that enables text-based configuration of the initial User, Role, and Permission objects
 * created at startup.
 * <p/>
 * Each User account definition specifies the username, password, and roles for a user.  Each Role definition
 * specifies a name and an optional collection of assigned Permissions.  Users can be assigned Roles, and Roles can be
 * assigned Permissions.  By transitive association, each User 'has' all of their Role's Permissions.
 * <p/>
 * User and user-to-role definitions are specified via the {@link #setUserDefinitions} method and
 * Role-to-permission definitions are specified via the {@link #setRoleDefinitions} method.
 *
 * @since 0.9
 */
public class TextConfigurationRealm extends SimpleAccountRealm {

    //TODO - complete JavaDoc

    private volatile String userDefinitions;
    private volatile String roleDefinitions;

    public TextConfigurationRealm() {
        super();
    }

    /**
     * Will call 'processDefinitions' on startup.
     *
     * @since 1.2
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-223">SHIRO-223</a>
     */
    @Override
    protected void onInit() {
        super.onInit();
        processDefinitions();
    }

    public String getUserDefinitions() {
        return userDefinitions;
    }

    /**
     * <p>Sets a newline (\n) delimited String that defines user-to-password-and-role(s) key/value pairs according
     * to the following format:
     * <p/>
     * <p><code><em>username</em> = <em>password</em>, role1, role2,...</code></p>
     * <p/>
     * <p>Here are some examples of what these lines might look like:</p>
     * <p/>
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
     * <p/>
     * <p>Each line within the string must define a role-to-permission(s) key/value mapping with the
     * equals character signifies the key/value separation, like so:</p>
     * <p/>
     * <p><code><em>rolename</em> = <em>permissionDefinition1</em>, <em>permissionDefinition2</em>, ...</code></p>
     * <p/>
     * <p>where <em>permissionDefinition</em> is an arbitrary String, but must people will want to use
     * Strings that conform to the {@link org.apache.shiro.authz.permission.WildcardPermission WildcardPermission}
     * format for ease of use and flexibility.  Note that if an individual <em>permissionDefinition</em> needs to
     * be internally comma-delimited (e.g. <code>printer:5thFloor:print,info</code>), you will need to surround that
     * definition with double quotes (&quot;) to avoid parsing errors (e.g.
     * <code>&quot;printer:5thFloor:print,info&quot;</code>).
     * <p/>
     * <p><b>NOTE:</b> if you have roles that don't require permission associations, don't include them in this
     * definition - just defining the role name in the {@link #setUserDefinitions(String) userDefinitions} is
     * enough to create the role if it does not yet exist.  This property is really only for configuring realms that
     * have one or more assigned Permission.
     *
     * @param roleDefinitions the role definitions to be parsed at initialization
     */
    public void setRoleDefinitions(String roleDefinitions) {
        this.roleDefinitions = roleDefinitions;
    }

    protected void processDefinitions() {
        try {
            processRoleDefinitions();
            processUserDefinitions();
        } catch (ParseException e) {
            String msg = "Unable to parse user and/or role definitions.";
            throw new ConfigurationException(msg, e);
        }
    }

    protected void processRoleDefinitions() throws ParseException {
        String roleDefinitions = getRoleDefinitions();
        if (roleDefinitions == null) {
            return;
        }
        Map<String, String> roleDefs = toMap(toLines(roleDefinitions));
        processRoleDefinitions(roleDefs);
    }

    protected void processRoleDefinitions(Map<String, String> roleDefs) {
        if (roleDefs == null || roleDefs.isEmpty()) {
            return;
        }
        for (Map.Entry<String,String> entry : roleDefs.entrySet()) {
            String rolename = entry.getKey();
            String value = entry.getValue();

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
        if (userDefinitions == null) {
            return;
        }

        Map<String, String> userDefs = toMap(toLines(userDefinitions));

        processUserDefinitions(userDefs);
    }

    protected void processUserDefinitions(Map<String, String> userDefs) {
        if (userDefs == null || userDefs.isEmpty()) {
            return;
        }
        for (Map.Entry<String,String> entry : userDefs.entrySet()) {
            String username = entry.getKey();
            String value = entry.getValue();

            String[] passwordAndRolesArray = StringUtils.split(value);

            String password = passwordAndRolesArray[0];

            SimpleAccount account = getUser(username);
            if (account == null) {
                account = new SimpleAccount(username, password, getName());
                add(account);
            }
            account.setCredentials(password);

            if (passwordAndRolesArray.length > 1) {
                for (int i = 1; i < passwordAndRolesArray.length; i++) {
                    String rolename = passwordAndRolesArray[i];
                    account.addRole(rolename);

                    SimpleRole role = getRole(rolename);
                    if (role != null) {
                        account.addObjectPermissions(role.getPermissions());
                    }
                }
            } else {
                account.setRoles(null);
            }
        }
    }

    protected static Set<String> toLines(String s) {
        LinkedHashSet<String> set = new LinkedHashSet<String>();
        try (Scanner scanner = new Scanner(s)) {
            while (scanner.hasNextLine()) {
                set.add(scanner.nextLine());
            }
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
            if (pair != null) {
                pairs.put(pair[0].trim(), pair[1].trim());
            }
        }

        return pairs;
    }
}
