package org.jsecurity.web.interceptor;

import java.util.Map;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface InterceptorBuilder {
    
    Map<String,Object> buildInterceptors( String config );
}
