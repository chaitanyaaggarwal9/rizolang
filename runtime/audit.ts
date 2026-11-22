/**
 * Rizo Lang runtime: the security audit log.
 *
 * An append-only record of security events, for investigating incidents:
 * who logged in (or failed to), who changed a password or a role, what was
 * deleted. Entries never contain passwords, tokens or request bodies; the
 * detail is one of a few fixed words or a model name. Entries older than the
 * retention period (365 days by default) are deleted automatically.
 */

export const AUDIT_TABLE = '"_rizo_audit"';

export type AuditAction =
  | "signup"
  | "login"
  | "login_failed"
  | "login_blocked"
  | "logout"
  | "logout_all"
  | "session_revoked"
  | "token_created"
  | "token_used"
  | "token_revoked"
  | "data_exported"
  | "records_expired"
  | "password_changed"
  | "password_check_failed"
  | "account_deleted"
  | "role_changed"
  | "passkey_added"
  | "passkey_removed"
  | "email_verified"
  | "email_changed"
  | "password_reset_requested"
  | "password_reset"
  | "admin_granted"
  | "record_deleted";

export interface AuditEntry {
  readonly action: AuditAction;
  /** The account that acted (or tried to), if known. */
  readonly userId?: string | undefined;
  /** The account or record affected, if any. */
  readonly targetId?: string | undefined;
  readonly ip?: string | undefined;
  /** A short fixed detail: a model name, a role, or a count. */
  readonly detail?: string | undefined;
}

export const AUDIT_SQL = {
  insert: `INSERT INTO ${AUDIT_TABLE} ("action", "user_id", "target_id", "ip", "detail") VALUES ($1, $2, $3, $4, $5)`,
  sweep: `DELETE FROM ${AUDIT_TABLE} WHERE "at" < now() - make_interval(days => $1)`,
  /** Newest first; optionally only entries where the account acted or was affected. */
  recent: `SELECT "id", "at", "action", "user_id" AS "userId", "target_id" AS "targetId", "ip", "detail" FROM ${AUDIT_TABLE}
WHERE ($1::uuid IS NULL OR "user_id" = $1::uuid OR "target_id" = $1::uuid) ORDER BY "at" DESC, "id" DESC LIMIT $2`,
} as const;

export const DEFAULT_AUDIT_RETENTION_DAYS = 365;

interface AuditDb {
  query(sql: string, values: unknown[]): Promise<{ readonly rows: readonly Record<string, unknown>[] }>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuidOrNull = (v: string | undefined): string | null => (v !== undefined && UUID.test(v) ? v : null);

export class Audit {
  readonly #db: AuditDb;
  readonly #log: (line: string) => void;
  constructor(db: AuditDb, log: (line: string) => void) {
    this.#db = db;
    this.#log = log;
  }

  /**
   * Record an event. If the log can't be written, the action still goes
   * ahead and the failure is logged: availability beats a missing entry.
   */
  async record(entry: AuditEntry): Promise<void> {
    try {
      await this.#db.query(AUDIT_SQL.insert, [
        entry.action,
        uuidOrNull(entry.userId),
        uuidOrNull(entry.targetId),
        entry.ip === undefined ? null : entry.ip.slice(0, 64),
        entry.detail === undefined ? null : entry.detail.slice(0, 100),
      ]);
    } catch (e) {
      this.#log(`warning audit log write failed (${entry.action}): ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async sweep(retentionDays: number): Promise<void> {
    await this.#db.query(AUDIT_SQL.sweep, [retentionDays]);
  }

  async recent(accountId: string | null, limit: number): Promise<readonly Record<string, unknown>[]> {
    return (await this.#db.query(AUDIT_SQL.recent, [accountId, limit])).rows;
  }
}
