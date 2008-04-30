/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * <p>Contains <a href="http://ehcache.sourceforge.net" target="_blank">Ehcache</a>-based implementations of
 * the JSecurity {@link org.jsecurity.cache.Cache CacheManager} and {@link org.jsecurity.cache.Cache Cache}
 * interfaces via the {@link org.jsecurity.cache.ehcache.EhCacheManager EhCacheManager} and
 * {@link org.jsecurity.cache.ehcache.EhCache EhCache} classes, respectively.
 *
 * <p>This package also contains a fail-safe <code>ehcache.xml</code> file that will be loaded by JSecurity when
 * ehcache components are used but no <code>ehcache.xml</code> file is located in the classpath (as would be
 * customary for ehcache usage).</p>
 */
package org.jsecurity.cache.ehcache;