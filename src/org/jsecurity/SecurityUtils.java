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
package org.jsecurity;

import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;

/**
 * Accesses the currently accessible <tt>Subject</tt> for the calling code.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class SecurityUtils {

    /**
     * Returns the currently accessible <tt>Subject</tt> available to the calling code.
     *
     * <p>This method is provided as a way of obtaining a <tt>Subject</tt> without having to resort to
     * implementation-specific methods.  It also allows the JSecurity team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * @return the currently accessible <tt>Subject</tt> accessible to the calling code.
     */
    public static Subject getSubject() {
        return ThreadContext.getSubject();
    }
}
