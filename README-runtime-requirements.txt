JSecurity Runtime Requirements
------------------------------

All 3rd party libraries mentioned below are in this distro's lib directory if you don't already have them.

Required jars
-------------
Ensure jsecurity.jar and Apache commons-logging.jar are in your application's classpath.

JDK 1.3 and 1.4 only: you must additionally include retroweaver.jar and its associated dependendencies
(they can be found in this distro's lib directory).


Feature-based dependencies
--------------------------
- If you want to use JSecurity's enterprise session management (heterogeneous clients, SSO support, etc):
  . include ehcache.jar and backport-util-concurrent.jar

- JSecurity Web Filter text-based config ('config' init param) in web.xml or JSecurity code Annotations:
  . include Jakarta commons-beanutils-core.jar
