/*
 * Copyright 2005-2008 Jeremy Haile
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
package org.jsecurity.cache;

import org.jsecurity.JSecurityException;

/**
 * Thrown if there is an error during cache operations.
 *
 * @author Jeremy Haile
 * @since 0.2
 */
public class CacheException extends JSecurityException {

    public CacheException() {
        super();
    }


    public CacheException( String message ) {
        super( message );
    }


    public CacheException( String message, Throwable cause ) {
        super( message, cause );
    }


    public CacheException( Throwable cause ) {
        super( cause );
    }
}