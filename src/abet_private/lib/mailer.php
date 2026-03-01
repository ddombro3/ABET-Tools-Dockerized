<?php
declare(strict_types=1);

/**
 * Minimal SMTP mail sender (no external libs).
 * Supports:
 * - SMTP over SSL (port 465)  => SMTP_ENCRYPTION=ssl
 * - SMTP + STARTTLS (port 587)=> SMTP_ENCRYPTION=starttls
 *
 * Uses env vars:
 * SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_FROM_NAME, SMTP_ENCRYPTION
 */

function abet_send_email(string $toEmail, string $subject, string $textBody, ?string &$error = null): bool {
  $error = null;

  $host = trim((string)getenv('SMTP_HOST'));
  $port = (int)(getenv('SMTP_PORT') ?: 0);
  $user = trim((string)getenv('SMTP_USER'));
  $pass = (string)getenv('SMTP_PASS');
  $from = trim((string)(getenv('SMTP_FROM') ?: $user));
  $fromName = trim((string)(getenv('SMTP_FROM_NAME') ?: 'ABET Tools'));
  $enc = strtolower(trim((string)(getenv('SMTP_ENCRYPTION') ?: 'ssl'))); // ssl | starttls

  if ($host === '' || $port === 0 || $user === '' || $pass === '' || $from === '') {
    $error = 'Missing SMTP env vars. Need SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM.';
    return false;
  }
  if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
    $error = 'Invalid recipient email.';
    return false;
  }

  $socketHost = $host;
  $timeout = 30;

  // For implicit SSL on 465, connect using ssl://
  if ($enc === 'ssl') {
    $socketHost = 'ssl://' . $host;
  }

  $fp = @fsockopen($socketHost, $port, $errno, $errstr, $timeout);
  if (!$fp) {
    $error = "Socket connect failed: {$errstr} ({$errno})";
    return false;
  }

  stream_set_timeout($fp, $timeout);

  $readResponse = function () use ($fp): array {
    $lines = [];
    $code = 0;

    while (!feof($fp)) {
      $line = fgets($fp, 515);
      if ($line === false) break;
      $lines[] = rtrim($line, "\r\n");

      if (preg_match('/^(\d{3})([ -])/', $line, $m)) {
        $code = (int)$m[1];
        if ($m[2] === ' ') break; // end of multi-line response
      } else {
        break;
      }
    }
    return [$code, implode("\n", $lines)];
  };

  $sendCmd = function (string $cmd, int $expectCode) use ($fp, $readResponse, &$error): bool {
    fwrite($fp, $cmd . "\r\n");
    [$code, $resp] = $readResponse();
    if ($code !== $expectCode) {
      $error = "SMTP error after '{$cmd}': expected {$expectCode}, got {$code}\n{$resp}";
      return false;
    }
    return true;
  };

  // Greeting
  [$code, $resp] = $readResponse();
  if ($code !== 220) {
    $error = "SMTP greeting failed: {$code}\n{$resp}";
    fclose($fp);
    return false;
  }

  $localHost = 'localhost';
  if (!$sendCmd("EHLO {$localHost}", 250)) { fclose($fp); return false; }

  // STARTTLS mode (port 587): upgrade to TLS
  if ($enc === 'starttls') {
    if (!$sendCmd("STARTTLS", 220)) { fclose($fp); return false; }
    $cryptoOk = stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if ($cryptoOk !== true) {
      $error = "Failed to enable TLS via STARTTLS.";
      fclose($fp);
      return false;
    }
    if (!$sendCmd("EHLO {$localHost}", 250)) { fclose($fp); return false; }
  }

  // AUTH LOGIN
  if (!$sendCmd("AUTH LOGIN", 334)) { fclose($fp); return false; }
  if (!$sendCmd(base64_encode($user), 334)) { fclose($fp); return false; }
  if (!$sendCmd(base64_encode($pass), 235)) { fclose($fp); return false; }

  // Envelope
  if (!$sendCmd("MAIL FROM:<{$from}>", 250)) { fclose($fp); return false; }
  if (!$sendCmd("RCPT TO:<{$toEmail}>", 250)) { fclose($fp); return false; }
  if (!$sendCmd("DATA", 354)) { fclose($fp); return false; }

  // Message headers + body (CRLF line endings required)
  $date = date('r');
  $msgId = sprintf('<%s.%s@%s>', time(), bin2hex(random_bytes(6)), $host);

  $headers = [
    "From: " . ($fromName !== '' ? "{$fromName} <{$from}>" : $from),
    "To: <{$toEmail}>",
    "Subject: " . $subject,
    "Date: {$date}",
    "Message-ID: {$msgId}",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
  ];

  // Dot-stuffing + normalize newlines
  $body = str_replace(["\r\n", "\r"], "\n", $textBody);
  $body = preg_replace('/^\./m', '..', $body);
  $body = str_replace("\n", "\r\n", $body);

  $data = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.\r\n";
  fwrite($fp, $data);

  [$code, $resp] = $readResponse();
  if ($code !== 250) {
    $error = "SMTP DATA accept failed: {$code}\n{$resp}";
    fclose($fp);
    return false;
  }

  // Quit
  fwrite($fp, "QUIT\r\n");
  fclose($fp);
  return true;
}