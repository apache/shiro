/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.apache.shiro.web.mgt;

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author mnn
 */
public class NonIniWebSecurityManagerTest extends AbstractWebSecurityManagerTest {
    
    private DefaultWebSecurityManager sm;
    
    @Before
    public void setup() {
        sm = new DefaultWebSecurityManager();
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniRealm.USERS_SECTION_NAME);
        section.put("lonestarr", "vespa");
        sm.setRealm(new IniRealm(ini));
    }

    @After
    public void tearDown() {
        sm.destroy();
        super.tearDown();
    }
    
    @Test
    public void testLoginNonWebSubject(){
        Subject.Builder builder = new Subject.Builder(sm);
        Subject subject = builder.buildSubject();
        subject.login(new UsernamePasswordToken("lonestarr", "vespa"));
        
    }
    
}
