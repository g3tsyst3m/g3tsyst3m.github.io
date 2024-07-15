---
title:  "Login"
layout: single
type: pages
permalink: /login-prompt/
---

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Form</title>
</head>
<body>
    <h2>Login Form</h2>
    <form action="https://files.thecybersanctuary.com/authenticate.php" method="post">
        <label for="user">Username:</label>
        <input type="text" id="user" name="user" required><br><br>
        
        <label for="pass">Password:</label>
        <input type="password" id="pass" name="pass" required><br><br>
        
        <input type="submit" value="Login">
    </form>
    <div id="message">
        <!-- Placeholder for displaying authentication result -->
    </div>
</body>
</html>
