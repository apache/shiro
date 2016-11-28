package org.apache.shiro.cdi;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.text.TextConfigurationRealm;
import org.apache.shiro.util.Initializable;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.Typed;

@ApplicationScoped
class StubConfiguration {

    @Typed({Realm.class, Initializable.class})
    @Produces
    private TextConfigurationRealm createTestRealm() {
        return new TextConfigurationRealm();
    }

    @Produces
    private PermissionResolver createPermissionResolver() {
        return new PermissionResolver() {
            @Override
            public Permission resolvePermission(String permissionString) {
                return null;
            }
        };
    }

    @Produces
    @ApplicationScoped
    private SecurityManager securityManager(@New DefaultSecurityManager securityManager) {
        return securityManager;
    }
}
