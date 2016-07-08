package org.apache.shiro.web.env

import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.web.filter.mgt.FilterChainResolver
import org.apache.shiro.web.mgt.WebSecurityManager

import javax.servlet.ServletContext

/**
 * Mock WebEnvironment, replaces IniWebEnvironment in EnvironmentLoader tests, to avoid extra dependencies.
 */
class MockWebEnvironment implements MutableWebEnvironment {

    @Override
    void setFilterChainResolver(FilterChainResolver filterChainResolver) {

    }

    @Override
    void setServletContext(ServletContext servletContext) {

    }

    @Override
    void setWebSecurityManager(WebSecurityManager webSecurityManager) {

    }

    @Override
    FilterChainResolver getFilterChainResolver() {
        return null
    }

    @Override
    ServletContext getServletContext() {
        return null
    }

    @Override
    WebSecurityManager getWebSecurityManager() {
        return null
    }

    @Override
    SecurityManager getSecurityManager() {
        return null
    }
}
