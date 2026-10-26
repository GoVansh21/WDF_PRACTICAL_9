<?php
require_once "db.php";

$message = "";
$messageType = "";
$username = "";
$email = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $token = $_POST["csrf_token"] ?? "";

    if (!is_string($token) ||
        !hash_equals($_SESSION["csrf_token"], $token)) {
        $message = "Invalid request. Please refresh the page.";
        $messageType = "danger";
    } else {
        $username = trim($_POST["username"] ?? "");
        $email = trim($_POST["email"] ?? "");
        $password = $_POST["password"] ?? "";
        $confirmPassword = $_POST["confirm_password"] ?? "";

        // Backend validation
        if (
            $username === "" ||
            strlen($username) < 3 ||
            strlen($username) > 50 ||
            !preg_match('/^[a-zA-Z0-9_]+$/', $username)
        ) {
            $message = "Username must be 3-50 characters and contain only letters, numbers, or underscores.";
            $messageType = "danger";
        } elseif (
            !filter_var($email, FILTER_VALIDATE_EMAIL) ||
            strlen($email) > 150
        ) {
            $message = "Please enter a valid email address.";
            $messageType = "danger";
        } elseif (strlen($password) < 8) {
            $message = "Password must contain at least 8 characters.";
            $messageType = "danger";
        } elseif ($password !== $confirmPassword) {
            $message = "Passwords do not match.";
            $messageType = "danger";
        } else {
            try {
                // Check duplicate username or email
                $stmt = $conn->prepare(
                    "SELECT username, email FROM users
                     WHERE username = ? OR email = ?"
                );
                $stmt->bind_param("ss", $username, $email);
                $stmt->execute();

                $result = $stmt->get_result();
                $duplicateUsername = false;
                $duplicateEmail = false;

                while ($row = $result->fetch_assoc()) {
                    if (strcasecmp($row["username"], $username) === 0) {
                        $duplicateUsername = true;
                    }

                    if (strcasecmp($row["email"], $email) === 0) {
                        $duplicateEmail = true;
                    }
                }

                if ($duplicateUsername && $duplicateEmail) {
                    $message = "Both username and email are already registered.";
                    $messageType = "danger";
                } elseif ($duplicateUsername) {
                    $message = "This username is already taken.";
                    $messageType = "danger";
                } elseif ($duplicateEmail) {
                    $message = "This email is already registered.";
                    $messageType = "danger";
                } else {
                    // Hash password before database insertion
                    $hashedPassword = password_hash(
                        $password,
                        PASSWORD_DEFAULT
                    );

                    $stmt = $conn->prepare(
                        "INSERT INTO users (username, email, password)
                         VALUES (?, ?, ?)"
                    );
                    $stmt->bind_param(
                        "sss",
                        $username,
                        $email,
                        $hashedPassword
                    );
                    $stmt->execute();

                    $message = "Registration successful! Your account has been created.";
                    $messageType = "success";

                    // Clear sensitive and submitted values
                    $username = "";
                    $email = "";
                    $password = "";
                    $confirmPassword = "";

                    // Rotate token after successful registration
                    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
                }
            } catch (mysqli_sql_exception $e) {
                // Unique database constraints also prevent duplicates
                if ((int)$e->getCode() === 1062) {
                    $message = "Username or email already exists. Please try another.";
                    $messageType = "danger";
                } else {
                    $message = "Registration could not be completed. Please try again.";
                    $messageType = "danger";
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure User Registration</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">
</head>
<body class="bg-light">

<div class="container py-5">
    <div class="card shadow mx-auto" style="max-width: 500px;">
        <div class="card-header bg-primary text-white text-center">
            <h3 class="mb-0">User Registration</h3>
        </div>

        <div class="card-body p-4">
            <?php if ($message !== ""): ?>
                <div class="alert alert-<?= htmlspecialchars($messageType) ?>"
                     role="alert">
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>

            <form method="post" action="register.php">
                <input type="hidden" name="csrf_token"
                       value="<?= htmlspecialchars($_SESSION["csrf_token"]) ?>">

                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" id="username" name="username"
                           class="form-control" required minlength="3"
                           maxlength="50" pattern="[A-Za-z0-9_]+"
                           title="Use letters, numbers, and underscores only."
                           autocomplete="username"
                           value="<?= htmlspecialchars($username) ?>">
                </div>

                <div class="mb-3">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" id="email" name="email"
                           class="form-control" required maxlength="150"
                           autocomplete="email"
                           value="<?= htmlspecialchars($email) ?>">
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" id="password" name="password"
                           class="form-control" required minlength="8"
                           autocomplete="new-password">
                    <div class="form-text">
                        Password must be at least 8 characters.
                    </div>
                </div>

                <div class="mb-3">
                    <label for="confirm_password" class="form-label">
                        Confirm Password
                    </label>
                    <input type="password" id="confirm_password"
                           name="confirm_password" class="form-control"
                           required minlength="8"
                           autocomplete="new-password">
                </div>

                <button type="submit" class="btn btn-primary w-100">
                    Register
                </button>
            </form>
        </div>
    </div>
</div>

</body>
</html>
