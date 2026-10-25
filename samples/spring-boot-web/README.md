Apache Shiro + Spring Boot Web Example
=================================

A Spring Boot example web application that show the usage of a user login, checking permissions, and annotation
protected methods.

Run the Example
---------------

```bash
mvn spring-boot:run
```

Browse to `http://localhost:8080/`

Path Matching
-------------

The starter's environment post-processor requests Ant path matching from Spring MVC when Boot still supports it.
If MVC instead uses Spring's native `PathPatternParser` (for example, when the Ant setting is no longer supported), the starter
uses Spring's parsed patterns for both Shiro filter-chain selection and path-aware filters.
Shiro chain definitions then use Spring path-pattern syntax, and invalid patterns fail during startup.
Matching remains case-insensitive by default, independently of MVC's parser setting, to preserve protection for
static resources on case-insensitive filesystems. Set `shiro.caseInsensitive=false` to explicitly opt into
case-sensitive matching. Shiro also retains its trailing-slash retry: `/admin` and `/admin/` select the same
restriction, even if MVC distinguishes those paths. Filter-chain definitions retain Shiro's first-match ordering
and deny-by-default fallback.
