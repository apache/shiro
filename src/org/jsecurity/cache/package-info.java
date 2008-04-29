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
 * Contains all caching-related interfaces and exceptions for performance-enhancing caching during runtime.
 *
 * <p>In good interface-driven design fashion, JSecurity uses the <tt>Cache</tt> and <tt>CacheManager</tt>
 * interfaces to separate implementation details from framework components.  A <tt>CacheManager</tt> is
 * responsible for creating and managing <tt>Cache</tt>s.  A <tt>Cache</tt> is, as its name might imply, is
 * a key/value data map.</p>
 *
 * <p>Common underlying <tt>CacheManager</tt> and <tt>Cache</tt> implementations can support anything from
 * simple map-based memory caches to more robust distributed network caches like Ehcache, JBoss Cache, JCS,
 * OSCache, Coherence, GigaSpaces and more.</p>
 */
package org.jsecurity.cache;