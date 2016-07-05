/*
 *  Licensed under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package org.apache.shiro.cdi;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;

@RunWith(PaxExam.class)
public abstract class AbstractCdiTest  {
    
    private static SimpleAccountRealm realm;
    private static DefaultSecurityManager securityManager;

    @BeforeClass
    public static void start() throws Exception {
        securityManager = new DefaultSecurityManager();
        SecurityUtils.setSecurityManager(securityManager);


        realm = new SimpleAccountRealm("test-realm");
        realm.addRole("role");
        realm.addAccount("foo", "bar", "role");
        realm.addAccount("bilbo", "precious", "hobbit");
        realm.setRolePermissionResolver(new RolePermissionResolver() {
            public Collection<Permission> resolvePermissionsInRole(String roleString) {
                if ("role".equals(roleString)) {
                    final Permission dp = new WildcardPermission("permission");
                    return Arrays.asList(dp);
                }
                return Collections.emptyList();
            }
        });
        securityManager.setRealm(realm);
    }

    @AfterClass
    public static void close() throws Exception {
        SecurityUtils.setSecurityManager(null);
    }
    
    protected String getRealmName() {
        return realm.getName();
    }
}
