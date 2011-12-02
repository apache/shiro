package org.apache.shiro.authc.credential

import org.apache.shiro.util.ByteSource

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: 9/20/11
 * Time: 3:38 PM
 * To change this template use File | Settings | File Templates.
 */
class DefaultPasswordServiceTest extends GroovyTestCase {

    void testDefault() {
        def passwordService = new DefaultPasswordService();

        def password = ByteSource.Util.bytes("12345")

        def formatted = passwordService.hashPassword(password)
        System.out.println "Formatted/stored password: $formatted"

        assertTrue passwordService.passwordsMatch(password, '$shiro1$SHA-512$300000$d07mwTTz3EHqQEdc5KBPCgzigcuwYmbfD3nw7ao7zmA=$B76M6PRqOl4kaScZjKHDWVcE08MwOrqTQyqmmPAIw9Sl0ONG/Rv7GxeUfc5fA3ujhxKJgGgDllDC1EchHFlncw==');
    }

}
