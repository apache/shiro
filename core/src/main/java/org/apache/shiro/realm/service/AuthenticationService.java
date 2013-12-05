package org.apache.shiro.realm.service;

import java.util.Set;

/**
 * This interface defines three method to fetch password/rolenames/permissions for usertoken authentication.
 * @author kimmking (kimmking@163.com)
 * @date 2013-12-5
 */
public interface AuthenticationService {

	/**
	 * @param username
	 * @return the password of the user
	 * @throws Exception
	 */
	SaltedPassword findSaltedPasswordByUserName(String username) throws Exception;

	/**
	 * @param username
	 * @return the roleName collection of the user
	 * @throws Exception
	 */
	Set<String> findRoleNamesForUserName(String username) throws Exception;

	/**
	 * @param username
	 * @param roleNames
	 * @return the permission string collection of the user
	 * @throws Exception
	 */
	Set<String> findPermissions(String username, Set<String> roleNames) throws Exception;

}
