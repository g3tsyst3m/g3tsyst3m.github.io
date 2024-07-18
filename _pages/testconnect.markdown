---
title:  "testconnect"
layout: single
type: pages
permalink: /test-connect/
---

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Protected AJAX Form</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <form id="secure-form" method="POST">
        <input type="text" name="username" id="username" placeholder="Username" required>
        <input type="hidden" name="csrf_token" id="csrf_token">
        <button type="submit">Submit</button>
    </form>

    <script>
        $(document).ready(function() {
            // Fetch the CSRF token from the server
            $.get('https://files.thecybersanctuary.com/generate_csrf_token.php', function(data) {
                const response = JSON.parse(data);
                $('#csrf_token').val(response.csrf_token);
            });

            // Handle form submission
            $('#secure-form').on('submit', function(e) {
                e.preventDefault();
                
                const formData = $(this).serialize();

                $.ajax({
                    url: 'https://files.thecybersanctuary.com/validate_csrf_token.php',
                    type: 'POST',
                    data: formData,
                    success: function(response) {
                        const res = JSON.parse(response);
                        alert(res.message);
                    }
                });
            });
        });
    </script>
</body>
</html>
