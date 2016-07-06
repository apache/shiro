Shiro Objects as Managed Beans
------------------------------

`shiro-cdi-core` provides the following Shiro objects as application-scoped managed beans:

* SecurityManager
* Subject
* Session

These beans are implemented as dynamic proxies which access the target object via `SecurityUtils.getSecurityManager()`. `shiro-cdi-core` does not itself instantiate a security manager.

Securing Methods with Shiro Annotations
---------------------------------------

Apache Shiro defines a set of annotations in package `org.apache.shiro.authz.annotation` which can be used to declare the required roles or permissions for invoking a given method. These annotations require a suitable enabling technology like aspects or interceptors. Apache Shiro supports Spring, Guice or AspectJ as enabling technologies. Shiro adds support for CDI in full-blown Java EE applications, in web-only applications with CDI (e.g. Tomcat + Weld), or in Java SE applications with CDI.
To enable Shiro annotations with CDI, include the `shiro-cdi-core` library in your application and enable the `ShiroInterceptor` in your beans.xml descriptor:
```xml
<beans>
    <interceptors>
        <class>org.apache.shiro.cdi.interceptor.ShiroInterceptor</class>
    </interceptors>          
</beans>
```

Managed Beans and Shiro INI Files
---------------------------------

INI files are the preferred configuration mechanism for Apache Shiro. In fact, these INI files can be regarded as a kind of poor man's bean context, defining a set of Shiro-flavoured managed beans.
In a CDI application, however, these INI-configured Shiro objects are not managed beans, as they are not instantiated by the CDI bean manager. `shiro-cdi-core` lets you reference CDI managed beans from Shiro INI files, so you can inject any transitive dependencies of Shiro objects by means of CDI.
To mark a managed bean as referenceable from Shiro INI files, simply add the `@ShiroIni` qualifier. The bean name can be set explicitly with a `@Named` qualifier. Otherwise, if Bean.getBeanClass() is a bean type of the given bean, the bean name will be the simple class name of this class, with the first letter converted to lower case.
Example:
```java
@ShiroIni
public class MyPasswordMatcher extends SimpleCredentialsMatcher {

   @Inject
   private MyDependency myDependency;

   // body omitted
}
```

```
[main]
iniRealm.credentialsMatcher = $myPasswordMatcher
```

CDI Support for Shiro Web Applications
--------------------------------------

`shiro-cdi-web` builds on `shiro-cdi-core` and provides a `CdiIniWebEnvironment`. To secure your web application with Apache Shiro and CDI support from Shiro, include the following in your `web.xml` descriptor:
```xml
<context-param>
    <param-name>shiroEnvironmentClass</param-name>
    <param-value>org.apache.shiro.cdi.web.CdiIniWebEnvironment</param-value>
</context-param>

<listener>
    <listener-class>org.apache.shiro.web.env.EnvironmentLoaderListener</listener-class>
</listener>

<filter>
    <filter-name>ShiroFilter</filter-name>
    <filter-class>org.apache.shiro.web.servlet.ShiroFilter</filter-class>
</filter>

<filter-mapping>
    <filter-name>ShiroFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

See `sample-cdi` for an example, which should work on any Java EE 6 server (tested on JBoss AS 7.2).