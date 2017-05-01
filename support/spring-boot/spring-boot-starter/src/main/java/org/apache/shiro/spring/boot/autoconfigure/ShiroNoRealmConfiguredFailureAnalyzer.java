package org.apache.shiro.spring.boot.autoconfigure;

import org.apache.shiro.spring.boot.autoconfigure.exception.NoRealmBeanConfiguredException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

public class ShiroNoRealmConfiguredFailureAnalyzer extends AbstractFailureAnalyzer<NoRealmBeanConfiguredException> {
 
 	@Override
 	protected FailureAnalysis analyze(Throwable rootFailure, NoRealmBeanConfiguredException cause) {
 		return new FailureAnalysis( "No bean of type 'org.apache.shiro.realm.Realm' found.", "Please create bean of type 'Realm' or add a shiro.ini in the root classpath (src/main/resources/shiro.ini) or in the META-INF folder (src/main/resources/META-INF/shiro.ini).", cause);
 	}
 
 }