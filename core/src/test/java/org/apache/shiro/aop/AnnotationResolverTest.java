package org.apache.shiro.aop;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

import java.lang.reflect.Method;

import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.junit.Test;
import static org.junit.Assert.*;


public class AnnotationResolverTest {
    @SuppressWarnings("unused")
    @RequiresRoles("root")
    private class MyFixture {
	public void operateThis() {}
        @RequiresUser()
        public void operateThat() {}
    }
    
    DefaultAnnotationResolver annotationResolver = new DefaultAnnotationResolver();

    @Test
    public void testAnnotationFoundFromClass() throws SecurityException, NoSuchMethodException {
	MyFixture myFixture = new MyFixture();
	MethodInvocation methodInvocation = createMock(MethodInvocation.class);
	Method method = MyFixture.class.getDeclaredMethod("operateThis");
        expect(methodInvocation.getMethod()).andReturn(method);
        expect(methodInvocation.getThis()).andReturn(myFixture);
        replay(methodInvocation);
	assertNotNull(annotationResolver.getAnnotation(methodInvocation, RequiresRoles.class));
    }
    
    @Test
    public void testAnnotationFoundFromMethod() throws SecurityException, NoSuchMethodException {
	MethodInvocation methodInvocation = createMock(MethodInvocation.class);
	Method method = MyFixture.class.getDeclaredMethod("operateThat");
        expect(methodInvocation.getMethod()).andReturn(method);
        replay(methodInvocation);
	assertNotNull(annotationResolver.getAnnotation(methodInvocation, RequiresUser.class));
    }
}

