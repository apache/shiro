<%@ page import="org.jsecurity.SecurityUtils" %>
<%@ include file="include.jsp" %>

<html>
<head>
    <link type="text/css" rel="stylesheet" href="<c:url value="jsecurity.css"/>" />
</head>
<body>
  <% SecurityUtils.getSubject().logout(); %>

  <h3>You have been logged out.</h3>

</body>
</html>