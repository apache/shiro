package org.jsecurity.web.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.mgt.SecurityManager;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.AntPathMatcher;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * Default implementation of the {@link UrlAuthorizationHandler} used by the {@link org.jsecurity.web.servlet.JSecurityFilter}
 * for authorizing users to access URLs.
 */
public class DefaultUrlAuthorizationHandler implements UrlAuthorizationHandler {

    protected static final String AUTHORIZATION_STRING_DELIMITER = ";";

    protected static final AuthorizationRequirement AUTHENTICATED_REQUIREMENT = new AuthenticatedRequirement();
    protected static final AuthorizationRequirement USER_REQUIREMENT = new UserRequirement();

    protected transient final Log log = LogFactory.getLog(getClass());

    protected SecurityManager securityManager;

    protected AntPathMatcher pathMatcher = new AntPathMatcher();

    protected Map<String, List<AuthorizationRequirement>> urlMap;

    public boolean configureUrlAuthorization(org.jsecurity.mgt.SecurityManager securityManager, FilterConfig config) {

        if( securityManager == null ) {
            throw new IllegalArgumentException( "SecurityManager cannot be null." );
        }

        this.securityManager = securityManager;

        String urlString = config.getInitParameter( "urls" );
        if( urlString != null ) {
            try {
                parseUrls( urlString );
            } catch (RuntimeException e) {
                log.error( "Error parsing URLs from authorization string.", e );
            }
            return true;
        }

        return false;
    }

    protected void parseUrls(String urlString) {

        Scanner scanner = new Scanner( urlString );
        urlMap = new HashMap<String,List<AuthorizationRequirement>>();
        while( scanner.hasNext() ) {

            String urlMapping = scanner.next();
            String[] parts = urlMapping.split( "=" );
            if( parts.length != 2 ) {
                throw new IllegalArgumentException( "Invalid URL mapping [" + urlMapping + "]. URL mappings must be of the format <urlPattern>=<authorization>." );
            }

            String urlPattern = parts[0];
            String authorizationString = parts[1];

            List<AuthorizationRequirement> reqs = buildRequirements( authorizationString );
            if( reqs != null ) {
                urlMap.put( urlPattern, reqs );
            }
        }
    }

    protected List<AuthorizationRequirement> buildRequirements(String authorizationString) {
        String[] authorizationParts = authorizationString.split(AUTHORIZATION_STRING_DELIMITER);

        List<AuthorizationRequirement> requirements = new ArrayList<AuthorizationRequirement>( authorizationParts.length );
        for( String part : authorizationParts ) {
            requirements.add( buildRequirement( part ) );
        }

        return requirements;
    }

    protected AuthorizationRequirement buildRequirement(String part) {
        AuthorizationRequirement requirement;

        part = part.trim();

        if( part.equals( "authenticated" ) ) {
            requirement = AUTHENTICATED_REQUIREMENT;

        } else if( part.equals( "user" ) ) {
            requirement = USER_REQUIREMENT;

        } else if( part.startsWith( "role" ) ) {
            String[] roleParts = part.split( "." );
            if( roleParts.length != 2 ) {
                throw new IllegalArgumentException( "Role string is not valid [" + part + "].  Should be of the form role:roleName." );
            }
            requirement = new RoleRequirement( roleParts[1] );

        } else if( part.startsWith( "permission" ) ) {
            String[] permissionParts = part.split( "." );
            if( permissionParts.length != 2 ) {
                throw new IllegalArgumentException( "Permission string is not valid [" + part + "].  Should be of the form permission:permissionString." );
            }
            requirement = new PermissionRequirement( permissionParts[1] );

        } else {
            throw new IllegalArgumentException( "Requirement string is not a valid authorization string [" + part + "]" );
        }

        return requirement;
    }


    public boolean isUserAuthorizedForRequest(HttpServletRequest request) {

        if( securityManager == null ) {
            throw new IllegalStateException( "Cannot authorize user until security manager is set.  Was configureUrlAuthorization invoked?" );
        }

        //todo Need to strip off context path here.  See Spring's UrlPathHelper.getPathWithinApplication()
        String requestURI = request.getRequestURI();

        // If URL path isn't matched, we assume that the user is authorized - so default to true
        boolean authorized = true;
        for( String url : urlMap.keySet() ) {

            // If the path does match, then set authorized to false if the subject isn't authorized
            if( pathMatcher.match( url, requestURI ) ) {
                List<AuthorizationRequirement> reqs = urlMap.get( url );

                Subject subject = securityManager.getSubject();
                if( !isSubjectAuthorizedForAll(subject, reqs) ) {
                    authorized = false;
                }
            }
        }
        return authorized;
    }


    private boolean isSubjectAuthorizedForAll(Subject subject, List<AuthorizationRequirement> reqs) {
        if( reqs == null || reqs.isEmpty() ) {
            throw new IllegalArgumentException( "Authorization requirements cannot be null or empty." );
        }

        boolean authorizedForAll = true;
        for( AuthorizationRequirement req : reqs ) {
            if( !req.isSubjectAuthorized( subject ) ) {
                authorizedForAll = false;
            }
        }
        return authorizedForAll;
    }
}
