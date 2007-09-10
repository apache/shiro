package org.jsecurity.cache;

/**
 * Interface implemented by components that utilize a CacheProvider and wish that CacheProvider to be supplied if
 * one is available.
 *
 * <p>This is used so internal security components that use a CacheProvider can be injected with it instead of having
 * to create one on their own.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public interface CacheProviderAware {

    void setCacheProvider( CacheProvider cacheProvider );
}
