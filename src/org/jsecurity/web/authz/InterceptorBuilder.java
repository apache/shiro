package org.jsecurity.web.authz;

import java.util.List;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface InterceptorBuilder {
    
    List buildInterceptors( String config );
}
