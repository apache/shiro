package org.jsecurity.web.interceptor;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface MatchingWebInterceptor extends WebInterceptor {

    void processPathConfig( String path, String config );
}
