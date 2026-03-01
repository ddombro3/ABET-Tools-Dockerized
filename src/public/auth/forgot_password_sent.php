<?php
declare(strict_types=1);

// require_once '/home/abet_private/config/config.php'; //local config path not available right now
require_once getenv('ABET_PRIVATE_DIR') . '/lib/auth.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$notice = $_SESSION['forgot_password_notice']
    ?? 'If an account exists for that email, a reset link has been sent.';

$devResetLink = $_SESSION['forgot_password_dev_reset_link'] ?? null;

// Clear flash messages after reading
unset($_SESSION['forgot_password_notice'], $_SESSION['forgot_password_dev_reset_link']);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Reset Link Sent</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Arial, sans-serif; background:#f5f6fa; margin:0; }
    .wrap { max-width: 560px; margin: 60px auto; background:#fff; border-radius:12px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,.08); }
    h1 { margin-top:0; }
    .notice { background:#eef7ee; color:#1f5f2b; padding:12px; border-radius:8px; }
    .dev { margin-top:14px; background:#fff8e1; color:#6b5200; padding:12px; border-radius:8px; word-break:break-all; }
    a { color:#8C1D40; text-decoration:none; }
    .links { margin-top:16px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Check Your Email</h1>

    <div class="notice">
      <?= htmlspecialchars($notice, ENT_QUOTES, 'UTF-8') ?>
    </div>

    <?php if (!empty($devResetLink)): ?>
      <div class="dev">
        <strong>Local Dev Only:</strong> Mailer not configured, so your reset link was logged/fallback-generated.<br><br>
        <a href="<?= htmlspecialchars($devResetLink, ENT_QUOTES, 'UTF-8') ?>">
          <?= htmlspecialchars($devResetLink, ENT_QUOTES, 'UTF-8') ?>
        </a>
      </div>
    <?php endif; ?>

    <div class="links">
      <a href="login.php">Back to Login</a>
    </div>
  </div>
</body>
</html>