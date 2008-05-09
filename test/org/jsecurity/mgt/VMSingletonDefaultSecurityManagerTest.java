/*
 * Copyright 2008 Les Hazlewood
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
package org.jsecurity.mgt;

import org.jsecurity.SecurityUtils;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.subject.Subject;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * TODO - Class JavaDoc
 *
 * @author Les Hazlewood
 * @since May 8, 2008 12:26:23 AM
 */
public class VMSingletonDefaultSecurityManagerTest {

    @Test
    public void testVMSingleton() {
        DefaultSecurityManager sm = new DefaultSecurityManager();
        sm.init();
        SecurityUtils.setSecurityManager(sm);

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login( token );
        subject.getSession().setAttribute("key", "value");
        assertTrue( subject.getSession().getAttribute("key").equals("value") );

        subject = SecurityUtils.getSubject();

        assertTrue( subject.isAuthenticated() );
        assertTrue( subject.getSession().getAttribute("key").equals("value") );

        sm.destroy();
    }
}
