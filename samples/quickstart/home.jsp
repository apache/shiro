<%@ include file="include.jsp" %>

<html>
<head>
    <link type="text/css" rel="stylesheet" href="<c:url value="/style.css"/>" />
</head>
<body>

  <h1>JSecurity Quickstart</h1>

  <p>Hi <jsec:guest>Guest</jsec:guest><jsec:user><jsec:principal/></jsec:user>!
      ( <jsec:user><a href="<c:url value="/logout.jsp"/>">Log out</a></jsec:user>
        <jsec:guest><a href="<c:url value="/login.jsp"/>">Log in</a> (sample accounts provided)</jsec:guest> )
  </p>

  <p>Welcome to the JSecurity Quickstart sample application.
      This page represents the home page of any web application.</p>

  <jsec:user><p>Visit your <a href="<c:url value="/account"/>">account page</a>.</p></jsec:user>
  <jsec:guest><p>If you want to access the user-only <a href="<c:url value="/account"/>">account page</a>,
      you will need to log-in first.</p></jsec:guest>

  <h2>Roles</h2>
  
  <p>To show some taglibs, here are the roles you have and don't have.  Log out and log back in under different user
      accounts to see different roles.</p>

  <h3>Roles you have</h3>

  <p>
      <jsec:hasRole name="root">root<br/></jsec:hasRole>
      <jsec:hasRole name="president">president<br/></jsec:hasRole>
      <jsec:hasRole name="darklord">darklord<br/></jsec:hasRole>
      <jsec:hasRole name="goodguy">goodguy<br/></jsec:hasRole>
      <jsec:hasRole name="schwartz">schwartz<br/></jsec:hasRole>
  </p>

  <h3>Roles you DON'T have</h3>

  <p>
      <jsec:lacksRole name="root">root<br/></jsec:lacksRole>
      <jsec:lacksRole name="president">president<br/></jsec:lacksRole>
      <jsec:lacksRole name="darklord">darklord<br/></jsec:lacksRole>
      <jsec:lacksRole name="goodguy">goodguy<br/></jsec:lacksRole>
      <jsec:lacksRole name="schwartz">schwartz<br/></jsec:lacksRole>
  </p>


</body>
</html>