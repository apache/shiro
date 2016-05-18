/*
 * Copyright 2016 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shiro.mgt.osgi.itest;

import java.io.File;
import java.net.URISyntaxException;
import javax.inject.Inject;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import static org.ops4j.pax.exam.CoreOptions.maven;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.karaf.options.KarafDistributionOption;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.features;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.features;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.features;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.karafDistributionConfiguration;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.karafDistributionConfiguration;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.karafDistributionConfiguration;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.keepRuntimeFolder;
import static org.ops4j.pax.exam.karaf.options.KarafDistributionOption.replaceConfigurationFile;
import org.ops4j.pax.exam.karaf.options.LogLevelOption;
import org.ops4j.pax.exam.options.MavenArtifactUrlReference;
import org.ops4j.pax.exam.options.MavenUrlReference;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerMethod;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;

/**
 *
 * @author mnn
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerMethod.class)
public class Integration {
    
    @Inject
    private BundleContext bundleContext;
    
    @Inject
    private Realm realm;
    
    @Inject
    private SecurityManager securityManager;

	 
	 @BeforeClass
    public static void beforeClass(){
	
    }
	 
	     @Configuration
public Option[] config() throws URISyntaxException {
    MavenArtifactUrlReference karafUrl = maven()
        .groupId("org.apache.karaf")
        .artifactId("apache-karaf")
        .versionAsInProject()
        .type("tar.gz");
    MavenUrlReference karafStandardRepo = maven()
        .groupId("org.apache.karaf.features")
        .artifactId("standard")
        .classifier("features")
        .type("xml")
        .versionAsInProject();
    MavenUrlReference karafEnterpriseRepo = maven()
        .groupId("org.apache.karaf.features")
        .artifactId("enterprise")
        .classifier("features")
        .type("xml")
        .versionAsInProject();
    MavenUrlReference shiroRepo = maven()
        .groupId("org.apache.shiro")
        .artifactId("shiro-karaf-feature")
        .classifier("features")
        .type("xml")
        .versionAsInProject();
    
    
    return new Option[] {
        karafDistributionConfiguration()
            .frameworkUrl(karafUrl)
            .unpackDirectory(new File("target/exam"))
            .useDeployFolder(false),
        keepRuntimeFolder(),
	features(karafStandardRepo, "webconsole"),
	features(shiroRepo, "Preset_Default"),
	KarafDistributionOption.logLevel(LogLevelOption.LogLevel.INFO),
	replaceConfigurationFile("etc/org.apache.shiro.realm.configadminrealm.cfg", new File(this.getClass().getClassLoader().getResource("org/apache/shiro/mgt/osgi/itest/configadminrealm.cfg").toURI())),
    };
    }

//    @Before
//    public void beforeTest() throws InterruptedException {
//        while (bundleContext.getBundle("mvn:org.apache.shiro/shiro-osgi-defaultsecuritymanager/0.1-SNAPSHOT").getState() != Bundle.ACTIVE) {
//            Thread.sleep(200);
//        }
//    }

    @Test @Ignore
    public void testPresence() throws Exception {
	System.in.read();
    }
    
    @Test
    public void testConfigRealm() throws Exception {
	//Thread.sleep(30000);
	Subject subject = SecurityUtils.getSubject();
	UsernamePasswordToken loginToken = new UsernamePasswordToken("admin", "admin".toCharArray());
	subject.login(loginToken);
	assertTrue(subject.hasRole("adminrole"));
	assertTrue(subject.isPermitted("adminpermission"));
    }
    
    
}
