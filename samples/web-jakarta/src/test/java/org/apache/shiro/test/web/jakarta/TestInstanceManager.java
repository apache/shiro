package org.apache.shiro.test.web.jakarta;

import java.lang.reflect.InvocationTargetException;
import javax.naming.NamingException;
import org.apache.tomcat.InstanceManager;

public class TestInstanceManager implements InstanceManager {

  @Override
  public Object newInstance(Class<?> clazz)
      throws IllegalAccessException, InvocationTargetException, NamingException, InstantiationException {
    return null;
  }

  @Override
  public Object newInstance(String className)
      throws IllegalAccessException, InvocationTargetException, NamingException, InstantiationException, ClassNotFoundException {
    return null;
  }

  @Override
  public Object newInstance(String fqcn, ClassLoader classLoader)
      throws IllegalAccessException, InvocationTargetException, NamingException, InstantiationException, ClassNotFoundException {
    return null;
  }

  @Override
  public void newInstance(Object o)
      throws IllegalAccessException, InvocationTargetException, NamingException {

  }

  @Override
  public void destroyInstance(Object o) throws IllegalAccessException, InvocationTargetException {

  }
}
