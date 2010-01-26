package org.apache.shiro.aspectj;

import java.util.Arrays;

import org.apache.shiro.aop.MethodInvocation;
import org.apache.shiro.authz.aop.AnnotationsAuthorizingMethodInterceptor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extends the annotations authorizing method interceptor class hierarchie to adapt
 * an aspectj {@link JoinPoint} into a {@link MethodInvocation} amd to perform the
 * authorization of method invocations.
 * 
 * @author J-C Desrochers
 * @author Kalle Korhonen
 * @since 1.0.0
 */
public class AspectjAnnotationsAuthorizingMethodInterceptor extends AnnotationsAuthorizingMethodInterceptor {
  /**
   * This class's private log instance.
   */
  private static final Logger log = LoggerFactory.getLogger(AspectjAnnotationsAuthorizingMethodInterceptor.class);

  /**
   * Performs the method interception of the before advice at the specified joint point.
   * 
   * @param aJoinPoint The joint point to intercept.
   * @throws Throwable If an error occurs berforming the method invocation.
   */
  protected void performBeforeInterception(JoinPoint aJoinPoint) throws Throwable {
    if (log.isTraceEnabled()) log.trace( "#### Invoking a method decorated with a Shiro annotation" +
	            "\n\tkind       : " + aJoinPoint.getKind() +
	            "\n\tjoinPoint  : " + aJoinPoint +
	            "\n\tannotations: " + Arrays.toString(((MethodSignature) aJoinPoint.getSignature()).getMethod().getAnnotations()) +
	            "\n\ttarget     : " + aJoinPoint.getTarget()
	            );
    
    // 1. Adapt the join point into a method invocation
    BeforeAdviceMethodInvocationAdapter mi = BeforeAdviceMethodInvocationAdapter.createFrom(aJoinPoint);

    // 2. Delegate the authorization of the method call to the super class
    super.invoke(mi);
  }
}
