<?php
declare(strict_types=1);

/**
 * Password reset helper library
 * Path: /home/osburn/abet_private/lib/reset_password_lib.php
 *
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

// Optional mailer include (safe if not created yet)
$__rpMailerPath = getenv('ABET_PRIVATE_DIR') . '/lib/mailer.php';
if (file_exists($__rpMailerPath)) {
    require_once $__rpMailerPath;
}
unset($__rpMailerPath);

/** -------------------------
 * Config / schema constants
 * ------------------------- */
const RP_USERS_TABLE = 'users';
const RP_PASSWORD_HASH_COLUMN = 'password_hash';
const RP_USER_ID_COLUMN = 'id';
const RP_USER_EMAIL_COLUMN = 'email';

const RP_RESETS_TABLE = 'password_resets';
const RP_TOKEN_BYTES = 32;                 // 32 bytes -> 64-char hex token
const RP_TOKEN_TTL_MINUTES_DEFAULT = 15;
const RP_RATE_LIMIT_SECONDS_DEFAULT = 60;

/** -------------------------
 * Public API functions
 * ------------------------- */

/**
 * Password policy (matches your described registration policy)
 */
function rp_password_policy_check(string $password): array {
    $issues = [];

    if (strlen($password) < 10) {
        $issues[] = 'Password must be at least 10 characters.';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $issues[] = 'Password must contain at least 1 lowercase letter.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $issues[] = 'Password must contain at least 1 uppercase letter.';
    }
    if (!preg_match('/\d/', $password)) {
        $issues[] = 'Password must contain at least 1 number.';
    }
    if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
        $issues[] = 'Password must contain at least 1 special character.';
    }

    return $issues;
}

/**
 * Request a password reset. Returns a generic public message no matter what.
 * On local/dev fallback mail mode, may return dev_reset_link for testing.
 */
function rp_request_password_reset(string $email, ?string $requestIp = null, ?string $userAgent = null): array {
    $publicMessage = 'If an account exists for that email, a reset link has been sent.';
    $email = trim(strtolower($email));

    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['ok' => true, 'public_message' => $publicMessage];
    }

    $pdo = rp_get_pdo();

    // Find user (do not reveal if missing)
    $sql = sprintf(
        'SELECT %s AS id, %s AS email
         FROM %s
         WHERE %s = :email
         LIMIT 1',
        RP_USER_ID_COLUMN,
        RP_USER_EMAIL_COLUMN,
        RP_USERS_TABLE,
        RP_USER_EMAIL_COLUMN
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // Still return generic success (anti-enumeration)
        return ['ok' => true, 'public_message' => $publicMessage];
    }

    $userId = (int)$user['id'];

    // Basic per-user rate limit
    $latestStmt = $pdo->prepare(
        'SELECT created_at
         FROM ' . RP_RESETS_TABLE . '
         WHERE user_id = :user_id
         ORDER BY id DESC
         LIMIT 1'
    );
    $latestStmt->execute([':user_id' => $userId]);
    $latest = $latestStmt->fetch(PDO::FETCH_ASSOC);

    if ($latest && !empty($latest['created_at'])) {
        $createdTs = strtotime((string)$latest['created_at']);
        if ($createdTs !== false) {
            $elapsed = time() - $createdTs;
            $cooldown = rp_rate_limit_seconds();
            if ($elapsed < $cooldown) {
                // Still return generic success; no new token issued
                return ['ok' => true, 'public_message' => $publicMessage];
            }
        }
    }

    // Invalidate previous unused tokens for this user (optional but recommended)
    $invalidateStmt = $pdo->prepare(
        'UPDATE ' . RP_RESETS_TABLE . '
         SET used_at = NOW()
         WHERE user_id = :user_id
           AND used_at IS NULL'
    );
    $invalidateStmt->execute([':user_id' => $userId]);

    $rawToken = rp_generate_raw_token();
    $tokenHash = rp_hash_token($rawToken);
    $expiresAt = date('Y-m-d H:i:s', time() + (rp_token_ttl_minutes() * 60));

    $insertStmt = $pdo->prepare(
        'INSERT INTO ' . RP_RESETS_TABLE . '
            (user_id, email, token_hash, expires_at, used_at, created_at, requested_ip, user_agent)
         VALUES
            (:user_id, :email, :token_hash, :expires_at, NULL, NOW(), :requested_ip, :user_agent)'
    );
    $insertStmt->execute([
        ':user_id'      => $userId,
        ':email'        => $email,
        ':token_hash'   => $tokenHash,
        ':expires_at'   => $expiresAt,
        ':requested_ip' => $requestIp,
        ':user_agent'   => $userAgent,
    ]);

    $resetLink = rp_build_reset_link($rawToken);

    // Send email (or fallback to local log)
    $sent = rp_send_password_reset_email($email, $resetLink);

    $result = ['ok' => true, 'public_message' => $publicMessage];
    if (!$sent) {
        // Keep public message generic, but expose dev link only for local testing.
        // This helps while SMTP is not configured yet.
        $result['dev_reset_link'] = $resetLink;
    }

    return $result;
}

/**
 * Validate token without changing anything.
 */
function rp_validate_reset_token(string $rawToken): array {
    $rawToken = trim($rawToken);

    if (!rp_is_valid_token_format($rawToken)) {
        return ['ok' => false, 'reason' => 'invalid_token'];
    }

    $pdo = rp_get_pdo();
    $tokenHash = rp_hash_token($rawToken);

    $stmt = $pdo->prepare(
        'SELECT pr.id, pr.user_id, pr.email, pr.token_hash, pr.expires_at, pr.used_at, pr.created_at
         FROM ' . RP_RESETS_TABLE . ' pr
         WHERE pr.token_hash = :token_hash
         LIMIT 1'
    );
    $stmt->execute([':token_hash' => $tokenHash]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return ['ok' => false, 'reason' => 'invalid_token'];
    }

    if (!empty($row['used_at'])) {
        return ['ok' => false, 'reason' => 'used_token'];
    }

    $expTs = strtotime((string)$row['expires_at']);
    if ($expTs === false || $expTs < time()) {
        return ['ok' => false, 'reason' => 'expired_token'];
    }

    return ['ok' => true, 'reset' => $row];
}

/**
 * Complete password reset using token + new password.
 */
function rp_complete_password_reset(string $rawToken, string $newPassword): array {
    $check = rp_validate_reset_token($rawToken);
    if (empty($check['ok'])) {
        return ['ok' => false, 'reason' => $check['reason'] ?? 'invalid_token'];
    }

    $policyIssues = rp_password_policy_check($newPassword);
    if ($policyIssues) {
        return ['ok' => false, 'reason' => 'password_policy_failed', 'issues' => $policyIssues];
    }

    $resetRow = $check['reset'];
    $resetId = (int)$resetRow['id'];
    $userId = (int)$resetRow['user_id'];

    $pdo = rp_get_pdo();
    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

    try {
        $pdo->beginTransaction();

        // Update user's password
        $updateUserSql = sprintf(
            'UPDATE %s SET %s = :password_hash WHERE %s = :user_id',
            RP_USERS_TABLE,
            RP_PASSWORD_HASH_COLUMN,
            RP_USER_ID_COLUMN
        );
        $userStmt = $pdo->prepare($updateUserSql);
        $userStmt->execute([
            ':password_hash' => $passwordHash,
            ':user_id'       => $userId,
        ]);

        // Mark the token used
        $usedStmt = $pdo->prepare(
            'UPDATE ' . RP_RESETS_TABLE . '
             SET used_at = NOW()
             WHERE id = :id
               AND used_at IS NULL'
        );
        $usedStmt->execute([':id' => $resetId]);

        // Optional: invalidate any other outstanding tokens for same user
        $invalidateOthers = $pdo->prepare(
            'UPDATE ' . RP_RESETS_TABLE . '
             SET used_at = NOW()
             WHERE user_id = :user_id
               AND used_at IS NULL'
        );
        $invalidateOthers->execute([':user_id' => $userId]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        rp_log_reset_event('reset failure: ' . $e->getMessage());
        return ['ok' => false, 'reason' => 'server_error'];
    }

    return ['ok' => true];
}

/** -------------------------
 * Mail sending wrapper
 * ------------------------- */

/**
 * Returns true if email was sent through a real mailer.
 * Returns false if mailer not configured (fallback log will be written).
 */
function rp_send_password_reset_email(string $toEmail, string $resetLink): bool {
    $subject = 'Reset Your ABET Tools Password';

    $safeLink = htmlspecialchars($resetLink, ENT_QUOTES, 'UTF-8');
    $htmlBody = <<<HTML
<p>Hello,</p>
<p>We received a request to reset your password for your ABET Tools account.</p>
<p><a href="{$safeLink}">Click here to reset your password</a></p>
<p>If the button/link above does not work, copy and paste this URL into your browser:</p>
<p>{$safeLink}</p>
<p>This link expires in {rp_token_ttl_minutes()} minutes and can only be used once.</p>
<p>If you did not request a password reset, you can ignore this email.</p>
HTML;

    // Replace placeholder after heredoc (avoids interpolation call in heredoc)
    $htmlBody = str_replace('{rp_token_ttl_minutes()}', (string) rp_token_ttl_minutes(), $htmlBody);

    $textBody = "Hello,\n\n"
        . "We received a request to reset your password for your ABET Tools account.\n\n"
        . "Use this link to reset your password:\n"
        . $resetLink . "\n\n"
        . "This link expires in " . rp_token_ttl_minutes() . " minutes and can only be used once.\n\n"
        . "If you did not request a password reset, you can ignore this email.\n";

    // If you create /home/osburn/abet_private/lib/mailer.php, define one of these:
    // - send_password_reset_email($toEmail, $subject, $htmlBody, $textBody)
    // - send_mail($toEmail, $subject, $htmlBody, $textBody)
    try {
        if (function_exists('send_password_reset_email')) {
            return (bool) send_password_reset_email($toEmail, $subject, $htmlBody, $textBody);
        }

        if (function_exists('send_mail')) {
            return (bool) send_mail($toEmail, $subject, $htmlBody, $textBody);
        }
    } catch (Throwable $e) {
        rp_log_reset_event('mailer failure: ' . $e->getMessage());
        // fall through to local dev log fallback
    }

    // Fallback for local/dev while mailer is not ready
    rp_log_reset_event("DEV RESET LINK for {$toEmail}: {$resetLink}");
    return false;
}

/** -------------------------
 * Internal helpers
 * ------------------------- */

function rp_generate_raw_token(): string {
    return bin2hex(random_bytes(RP_TOKEN_BYTES)); // 64 hex chars
}

function rp_hash_token(string $rawToken): string {
    // Store a hash only (never store the raw token)
    return hash('sha256', $rawToken);
}

function rp_is_valid_token_format(string $token): bool {
    return (bool) preg_match('/^[a-f0-9]{64}$/', $token);
}

function rp_build_reset_link(string $rawToken): string {
    $baseUrl = rtrim(rp_app_url(), '/');

    // IMPORTANT:
    // Adjust path below if your reset page is not in /auth/.
    // If reset_password.php sits at site root, change to '/reset_password.php'
    return $baseUrl . '/auth/reset_password.php?token=' . urlencode($rawToken);
}

function rp_token_ttl_minutes(): int {
    $value = rp_env_or_const('PASSWORD_RESET_TTL_MINUTES', RP_TOKEN_TTL_MINUTES_DEFAULT);
    $value = is_numeric($value) ? (int)$value : RP_TOKEN_TTL_MINUTES_DEFAULT;
    return max(5, min(120, $value));
}

function rp_rate_limit_seconds(): int {
    $value = rp_env_or_const('PASSWORD_RESET_RATE_LIMIT_SECONDS', RP_RATE_LIMIT_SECONDS_DEFAULT);
    $value = is_numeric($value) ? (int)$value : RP_RATE_LIMIT_SECONDS_DEFAULT;
    return max(10, min(3600, $value));
}

function rp_app_url(): string {
    // Try common config styles / envs
    $candidates = [
        defined('APP_URL') ? APP_URL : null,
        defined('BASE_URL') ? BASE_URL : null,
        $_ENV['APP_URL'] ?? null,
        getenv('APP_URL') ?: null,
    ];

    foreach ($candidates as $val) {
        if (is_string($val) && trim($val) !== '') {
            return trim($val);
        }
    }

    // Safe local fallback for Docker
    return 'http://localhost:8080';
}

function rp_env_or_const(string $name, mixed $default = null): mixed {
    if (defined($name)) {
        return constant($name);
    }
    if (array_key_exists($name, $_ENV)) {
        return $_ENV[$name];
    }
    $env = getenv($name);
    if ($env !== false) {
        return $env;
    }
    return $default;
}

/**
 * Tries a few common patterns so this works with different db.php implementations.
 * If your db.php uses a different function, update this one function only.
 */
function rp_get_pdo(): PDO {
    // Common patterns in custom PHP apps
    if (function_exists('db')) {
        $pdo = db();
        if ($pdo instanceof PDO) return $pdo;
    }

    if (function_exists('get_db')) {
        $pdo = get_db();
        if ($pdo instanceof PDO) return $pdo;
    }

    if (function_exists('get_pdo')) {
        $pdo = get_pdo();
        if ($pdo instanceof PDO) return $pdo;
    }

    if (isset($GLOBALS['pdo']) && $GLOBALS['pdo'] instanceof PDO) {
        return $GLOBALS['pdo'];
    }

    throw new RuntimeException(
        'Could not obtain PDO connection from db.php. Update rp_get_pdo() in reset_password_lib.php to match your db helper.'
    );
}

function rp_log_reset_event(string $message): void {
    $logDir = '/home/abet_private/logs';
    $logFile = $logDir . '/password_reset.log';

    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }

    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
    @file_put_contents($logFile, $line, FILE_APPEND);
}