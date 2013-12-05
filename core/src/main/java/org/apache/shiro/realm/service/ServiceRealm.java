package org.apache.shiro.realm.service;

import java.util.Set;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JDBCRealm can directly access database to fetch password/roles/permissions,
 * but it uses its own private data access method, sometimes differently with
 * the approach in our projects.
 * <p/>
 * ServiceRealm provides a way to integration with your UserManager classes in
 * your project. So, you can use your services to access database or other ways by unified
 * Data Access Layer. Such as ibatis/mybatis or hibernate or mock-service etc.
 * 
 * @author kimmking (kimmking.cn@gmail.com)
 * @date 2013-12-5
 */
public class ServiceRealm extends AuthorizingRealm {

	private static final Logger log = LoggerFactory.getLogger(ServiceRealm.class);

	boolean useSalt = false;
	AuthenticationService authencationService;

	public boolean isUseSalt() {
		return useSalt;
	}

	public void setUseSalt(boolean useSalt) {
		this.useSalt = useSalt;
	}

	public AuthenticationService getAuthorizingService() {
		return authencationService;
	}

	public void setAuthorizingService(AuthenticationService authorizingService) {
		this.authencationService = authorizingService;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();

		if (username == null) {
			throw new AccountException("Null usernames are not allowed by this realm.");
		}

		SimpleAuthenticationInfo info = null;
		try {
			SaltedPassword saltedPassword = authencationService.findSaltedPasswordByUserName(username);

			String password = saltedPassword.getPassword();
			if (password == null) {
				throw new UnknownAccountException("No account found for user [" + username + "]");
			}

			info = new SimpleAuthenticationInfo(username, password, getName());

			if (useSalt) {
				String salt = saltedPassword.getSalt();
				if (StringUtils.hasText(salt))
					info.setCredentialsSalt(ByteSource.Util.bytes(salt));
				else
					info.setCredentialsSalt(ByteSource.Util.bytes(username));
			}

		} catch (Exception e) {
			final String message = "There was an error while authenticating user [" + username + "]";
			if (log.isErrorEnabled()) {
				log.error(message, e);
			}

			throw new AuthenticationException(message, e);
		}

		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// null usernames are invalid
		if (principals == null) {
			throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
		}

		String username = (String) getAvailablePrincipal(principals);

		Set<String> roleNames = null;
		Set<String> permissions = null;
		try {
			// Retrieve roles and permissions from service
			roleNames = authencationService.findRoleNamesForUserName(username);
			permissions = authencationService.findPermissions(username, roleNames);

		} catch (Exception e) {
			final String message = "There was an error while authorizing user [" + username + "]";
			if (log.isErrorEnabled()) {
				log.error(message, e);
			}

			throw new AuthorizationException(message, e);
		} finally {
		}

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
		info.setStringPermissions(permissions);
		return info;
	}

}
