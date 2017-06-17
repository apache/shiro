package org.apache.shiro.env;

import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

/**
 * Basic usage:<p>
 * <code>
 * Environment env = new BasicIniEnvironment("classpath:shiro.ini");
 * SecurityManager securityManager = env.getSecurityManager();
 * </code>
 *
 */
public class BasicIniEnvironment extends DefaultEnvironment {
    public BasicIniEnvironment(Ini ini) {
        setSecurityManager(new IniSecurityManagerFactory(ini).getInstance());
    }

    public BasicIniEnvironment(String iniResourcePath) {
        this(Ini.fromResourcePath(iniResourcePath));
    }
}
