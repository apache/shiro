package org.apache.shiro.aspectj;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;

/**
 * Aspect that adds a before advice for each invocation of an annotated method.
 * 
 * @author J-C Desrochers
 */
@Aspect()
public class ShiroAnnotationAuthorizingAspect {

  private static final String pointCupExpression =
          "execution(@org.apache.shiro.authz.annotation.RequiresAuthentication * *(..)) || " +
          "execution(@org.apache.shiro.authz.annotation.RequiresGuest * *(..)) || " +
          "execution(@org.apache.shiro.authz.annotation.RequiresPermissions * *(..)) || " +
          "execution(@org.apache.shiro.authz.annotation.RequiresRoles * *(..)) || " +
          "execution(@org.apache.shiro.authz.annotation.RequiresUser * *(..))";
  
  @Pointcut(pointCupExpression)
  void anyShiroAnnotatedMethodCall(JoinPoint thisJoinPoint) {
  }
  
  private AspectjAnnotationsAuthorizingMethodInterceptor interceptor =
          new AspectjAnnotationsAuthorizingMethodInterceptor();

  @Before("anyShiroAnnotatedMethodCall(thisJoinPoint)")
  public void executeAnnotatedMethod(JoinPoint thisJoinPoint) throws Throwable {
    interceptor.performBeforeInterception(thisJoinPoint);
  }
}
