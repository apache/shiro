package org.apache.isis.security.shiro;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;

public class HttpHeaderLdapRealm extends IsisLdapRealm {
    private static final Logger log = LoggerFactory.getLogger(HttpHeaderLdapRealm.class);

    @Override
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
        Object principal = token.getPrincipal();
        log.debug("Trusting user '{}' through HTTP header", principal);
        return createAuthenticationInfo(token, principal, null, null);
    }
}
