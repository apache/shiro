/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.testing.jakarta.ee;

import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;

@Named
@ApplicationScoped
public class PropertyRealm extends IniRealm {
    @Getter
    @Setter
    private IniRealm iniRealm;

    @Override
    protected void onInit() {
        setName(getClass().getName());
        setIni(iniRealm.getIni());
        super.onInit();
    }

    @Override
    @SuppressWarnings("MagicNumber")
    protected void processUserDefinitions(Map<String, String> userDefs) {
        if (userDefs == null || userDefs.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : userDefs.entrySet()) {
            String username = entry.getKey();
            String value = entry.getValue();

            String[] passwordAndRolesArray = StringUtils.split(value);

            // the first token is expected to be the password.
            String password = passwordAndRolesArray[0];

            SimpleAccount account = getUser(username);
            if (account == null) {
                var pc = new SimplePrincipalCollection();
                pc.add(username, getName());
                pc.add(5, getName());
                pc.add(new PropertyPrincipal(username), getName());
                account = new SimpleAccount(pc, password, getName());
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
}
