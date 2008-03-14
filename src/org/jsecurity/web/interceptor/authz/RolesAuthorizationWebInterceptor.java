package org.jsecurity.web.interceptor.authz;

import org.jsecurity.subject.Subject;
import static org.jsecurity.util.StringUtils.split;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class RolesAuthorizationWebInterceptor extends AuthorizationWebInterceptor {

    public void processPathConfig(String path, String config) {
        if ( config != null ) {
            String[] values = split(config);
            if ( values != null ) {
                Set<String> set = new LinkedHashSet<String>( Arrays.asList(values) );
                this.appliedPaths.put(path, set);
            }
        }
    }

    @SuppressWarnings({"unchecked"})
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        Subject subject = getSubject(request, response);
        Set<String> roles = (Set<String>)mappedValue;

        if ( roles != null && !roles.isEmpty() ) {
            if ( roles.size() == 1 ) {
                if ( !subject.hasRole(roles.iterator().next()) ) {
                    issueRedirect(request,response);
                }
            } else {
                if ( !subject.hasAllRoles(roles) ) {
                    issueRedirect(request,response);
                }
            }
        }

        return true;
    }
}
