<%@ include file="include.jsp" %>

<html>

<head>
    <link type="text/css" rel="stylesheet" href="<c:url value="/jsecurity.css"/>"/>
</head>

<body>

    <div id="contentBox">
        <img src="<c:url value="/logo.png"/>" style="margin-top:20px; border:0"/><br/>

        <h2>You have successfully logged in as <jsecurity:principal/>.</h2>

        Session ID: ${subjectSession.id}

        <h3>Session Attribute Keys</h3>
        <ul>
        <c:forEach items="${subjectSession.attributeKeys}" var="key">
                  <li>${key}</li>
        </c:forEach>
        </ul>

        <p style="font-weight: bold;">
            <jsecurity:hasRole name="role1">You have role 1.<br/></jsecurity:hasRole>
            <jsecurity:lacksRole name="role1">You do not have role 1.<br/></jsecurity:lacksRole>
            <jsecurity:hasRole name="role2">You have role 2.<br/></jsecurity:hasRole>
            <jsecurity:lacksRole name="role2">You do not have role 2.<br/></jsecurity:lacksRole>
        </p>

        <form action="<c:url value="/s/index"/>" method="POST">
            Enter value here to store in session: <input type="text" name="value" value="${command.value}" size="30"/>
            <input type="submit" value="Save"/>
            <button type="button" onclick="document.location.href='<c:url value="/s/index"/>';">Refresh</button>
        </form>


        <p>
            Click <a href="<c:url value="/s/jsecurity.jnlp?sessionId=${subjectSession.id}"/>">here</a> to launch webstart application.
        </p>


        <p>
            Click <a href="<c:url value="/s/logout"/>">here</a> to logout.
        </p>
    </div>
</body>
</html>