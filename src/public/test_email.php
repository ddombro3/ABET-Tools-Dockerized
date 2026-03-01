<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

$abetPrivateDir = rtrim((string)getenv('ABET_PRIVATE_DIR'), '/');
require_once $abetPrivateDir . '/lib/mailer.php';

$sent = false;
$err = null;

$to = '';
$subject = 'Hello world SMTP test';
$message = "Hello from ABET Tools!\nSent at: " . date('c');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $to = trim((string)($_POST['to'] ?? ''));
  $subject = trim((string)($_POST['subject'] ?? $subject));
  $message = (string)($_POST['message'] ?? $message);

  $sent = abet_send_email($to, $subject, $message, $err);
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>SMTP Test</title></head>
<body style="font-family:system-ui;max-width:720px;margin:40px auto;">
  <h2>SMTP Test Email</h2>

  <?php if ($sent): ?>
    <p style="padding:10px;border:1px solid #7ad49b;background:#e8fff0;">✅ Sent to <b><?= htmlspecialchars($to) ?></b></p>
  <?php elseif ($err): ?>
    <p style="padding:10px;border:1px solid #e07a7a;background:#ffecec;">❌ <?= nl2br(htmlspecialchars($err)) ?></p>
  <?php endif; ?>

  <form method="post">
    <label>To:</label><br>
    <input name="to" style="width:100%;padding:8px" placeholder="you@example.com" required><br><br>

    <label>Subject:</label><br>
    <input name="subject" style="width:100%;padding:8px" value="<?= htmlspecialchars($subject) ?>"><br><br>

    <label>Message:</label><br>
    <textarea name="message" rows="8" style="width:100%;padding:8px"><?= htmlspecialchars($message) ?></textarea><br><br>

    <button type="submit" style="padding:10px 14px;">Send</button>
  </form>

  <p><b>Delete this file after testing:</b> <code>test_email.php</code></p>
</body>
</html>