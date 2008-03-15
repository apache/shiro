package org.jsecurity.web.interceptor;

/**
 * A PathConfigWebInterceptor is a <code>WebInterceptor</code> that can process configuration entries on a
 * per path (per url) basis.
 * 
 * @author Les Hazlewood
 * @since 0.9
 */
public interface PathConfigWebInterceptor extends WebInterceptor {

    void processPathConfig( String path, String config );
}
