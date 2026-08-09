/**
 * The capability catalogue: which module members mean what.
 *
 * Everything here is *observation vocabulary*, not verdicts. `child_process` is
 * on this list because a package that spawns processes is worth an inventory
 * entry, not because spawning processes is wrong — most build tooling in the
 * registry does it. The weighting of these observations lives in
 * `docs/RISK_MODEL.md` and the risk engine, deliberately far away from here.
 *
 * Module names are stored without the `node:` prefix; the resolver normalises
 * before lookup so `node:fs` and `fs` are one capability.
 */

/** Node's process-spawning surface. */
export const CHILD_PROCESS_MODULE = "child_process";
export const PROCESS_EXECUTION_MEMBERS: ReadonlySet<string> = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
  "fork",
]);

/** Members whose first argument is a full shell command line, not an argv[0]. */
export const SHELL_COMMAND_MEMBERS: ReadonlySet<string> = new Set(["exec", "execSync"]);

/** Built-in modules that move bytes off the machine. */
export const NETWORK_MODULES: ReadonlySet<string> = new Set([
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dgram",
  "dns",
  "dns/promises",
]);

/**
 * Widely-used HTTP clients. Included because "does this package make outbound
 * requests" should not depend on whether it uses the standard library, and
 * because a package that pulls in an HTTP client and never uses it is rare.
 */
export const NETWORK_PACKAGES: ReadonlySet<string> = new Set([
  "axios",
  "node-fetch",
  "got",
  "undici",
  "request",
  "superagent",
  "needle",
  "phin",
  "isomorphic-fetch",
  "cross-fetch",
  "form-data",
  "ws",
  "socket.io-client",
]);

/** Ambient network entry points. */
export const NETWORK_GLOBALS: ReadonlySet<string> = new Set([
  "fetch",
  "XMLHttpRequest",
  "WebSocket",
  "EventSource",
]);

/** DNS members that can carry data out in a hostname label. */
export const DNS_MEMBERS: ReadonlySet<string> = new Set([
  "resolve",
  "resolve4",
  "resolve6",
  "resolveTxt",
  "resolveAny",
  "lookup",
  "promises.resolve",
  "promises.resolveTxt",
  "promises.lookup",
]);

export const FILESYSTEM_MODULES: ReadonlySet<string> = new Set([
  "fs",
  "fs/promises",
  "graceful-fs",
  "fs-extra",
]);

export const FILESYSTEM_READ_MEMBERS: ReadonlySet<string> = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "readdir",
  "readdirSync",
  "open",
  "openSync",
  "read",
  "readSync",
  "realpath",
  "realpathSync",
  "readlink",
  "readlinkSync",
  "readJson",
  "readJsonSync",
  "opendir",
  "opendirSync",
]);

export const FILESYSTEM_WRITE_MEMBERS: ReadonlySet<string> = new Set([
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "createWriteStream",
  "write",
  "writeSync",
  "mkdir",
  "mkdirSync",
  "mkdtemp",
  "mkdtempSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "unlink",
  "unlinkSync",
  "rename",
  "renameSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "symlink",
  "symlinkSync",
  "link",
  "linkSync",
  "truncate",
  "truncateSync",
  "chmod",
  "chmodSync",
  "chown",
  "chownSync",
  "writeJson",
  "writeJsonSync",
  "outputFile",
  "outputFileSync",
  "remove",
  "removeSync",
  "emptyDir",
  "emptyDirSync",
]);

/** Members that make a file executable — the last step of a dropper. */
export const PERMISSION_MEMBERS: ReadonlySet<string> = new Set(["chmod", "chmodSync"]);

export const OS_MODULE = "os";
/**
 * Host fingerprinting surface. Individually mundane — `os.platform()` decides
 * which prebuilt binary to download in thousands of honest packages.
 */
export const HOST_RECON_MEMBERS: ReadonlySet<string> = new Set([
  "hostname",
  "userInfo",
  "networkInterfaces",
  "cpus",
  "totalmem",
  "freemem",
  "release",
  "type",
  "uptime",
  "machine",
]);

/** Lower-signal environment description, kept separate from recon. */
export const HOST_DESCRIPTION_MEMBERS: ReadonlySet<string> = new Set([
  "platform",
  "arch",
  "tmpdir",
  "endianness",
  "version",
]);

export const HOME_DIRECTORY_MEMBERS: ReadonlySet<string> = new Set(["homedir"]);

/** `process` members that describe the host or the running user. */
export const PROCESS_RECON_MEMBERS: ReadonlySet<string> = new Set([
  "getuid",
  "geteuid",
  "getgid",
  "getegid",
  "getgroups",
  "platform",
  "arch",
  "version",
  "versions",
  "pid",
  "ppid",
  "title",
  "execPath",
  "argv0",
]);

export const VM_MODULE = "vm";
export const VM_EXECUTION_MEMBERS: ReadonlySet<string> = new Set([
  "runInThisContext",
  "runInNewContext",
  "runInContext",
  "compileFunction",
  "Script",
  "SourceTextModule",
]);

/** Globals that turn a string into running code. */
export const DYNAMIC_EXECUTION_GLOBALS: ReadonlySet<string> = new Set([
  "eval",
  "Function",
]);

/** Base64/hex decoding entry points. */
export const DECODE_GLOBALS: ReadonlySet<string> = new Set(["atob", "unescape"]);

export const CRYPTO_MODULE = "crypto";
export const CIPHER_MEMBERS: ReadonlySet<string> = new Set([
  "createCipheriv",
  "createDecipheriv",
  "createCipher",
  "createDecipher",
  "privateDecrypt",
  "publicEncrypt",
]);

/** Modules whose whole purpose is loading a compiled native addon. */
export const NATIVE_LOADER_MODULES: ReadonlySet<string> = new Set([
  "bindings",
  "node-gyp-build",
  "@mapbox/node-pre-gyp",
  "node-pre-gyp",
  "prebuild-install",
  "@napi-rs/cli",
]);

/**
 * Environment variables that name a credential.
 *
 * Named access is *purposeful*: the package told us exactly what it wants. That
 * is a different observation from `process.env.NODE_ENV`, and it is the reason
 * this list is names rather than a generic "looks secret" heuristic — a
 * heuristic on the name would fire on `TOKEN_BUCKET_SIZE`.
 */
export const SECRET_ENVIRONMENT_NAMES: ReadonlySet<string> = new Set([
  "NPM_TOKEN",
  "NPM_AUTH_TOKEN",
  "NODE_AUTH_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITHUB_PAT",
  "GITLAB_TOKEN",
  "CI_JOB_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GCP_SERVICE_ACCOUNT_KEY",
  "AZURE_CLIENT_SECRET",
  "DOCKER_PASSWORD",
  "DOCKERHUB_TOKEN",
  "SSH_PRIVATE_KEY",
  "SLACK_TOKEN",
  "STRIPE_SECRET_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "SENTRY_AUTH_TOKEN",
  "VERCEL_TOKEN",
  "NETLIFY_AUTH_TOKEN",
  "CLOUDFLARE_API_TOKEN",
  "CIRCLE_TOKEN",
  "CODECOV_TOKEN",
  "TWINE_PASSWORD",
  "PYPI_TOKEN",
  "HEROKU_API_KEY",
]);

/** Environment names that describe the environment and nothing else. */
export const MUNDANE_ENVIRONMENT_NAMES: ReadonlySet<string> = new Set([
  "NODE_ENV",
  "CI",
  "DEBUG",
  "PORT",
  "HOME",
  "PATH",
  "TMPDIR",
  "TEMP",
  "TMP",
  "USER",
  "SHELL",
  "TERM",
  "LANG",
  "PWD",
  "NODE_OPTIONS",
  "npm_lifecycle_event",
  "npm_config_prefix",
  "npm_package_name",
  "npm_package_version",
  "FORCE_COLOR",
  "NO_COLOR",
  "COLORTERM",
]);

export type SensitivePathClass =
  | "PACKAGE_MANAGER_CREDENTIAL"
  | "SSH_KEY"
  | "CLOUD_CREDENTIAL"
  | "SHELL_HISTORY"
  | "BROWSER_OR_WALLET"
  | "GENERIC_CREDENTIAL";

export interface SensitivePathPattern {
  /** Lowercased substring searched for inside a string literal. */
  readonly needle: string;
  readonly class: SensitivePathClass;
  readonly description: string;
}

/**
 * Credential-bearing paths.
 *
 * Matched as substrings of *already-parsed string literals* — never against
 * raw file text. Substring matching inside a literal is the supplementary,
 * justified use of pattern matching described in the charter: the AST tells us
 * this is a string the code uses, and the pattern tells us which file it names.
 *
 * These are ordered longest-context-first so `~/.aws/credentials` is reported
 * as a cloud credential rather than as a bare `.aws`.
 */
export const SENSITIVE_PATH_PATTERNS: readonly SensitivePathPattern[] = [
  {
    needle: ".npmrc",
    class: "PACKAGE_MANAGER_CREDENTIAL",
    description: "npm auth configuration (may contain a registry token)",
  },
  {
    needle: ".yarnrc.yml",
    class: "PACKAGE_MANAGER_CREDENTIAL",
    description: "Yarn configuration (may contain npmAuthToken)",
  },
  {
    needle: ".yarnrc",
    class: "PACKAGE_MANAGER_CREDENTIAL",
    description: "Yarn configuration",
  },
  {
    needle: ".pypirc",
    class: "PACKAGE_MANAGER_CREDENTIAL",
    description: "PyPI upload credentials",
  },
  {
    needle: ".netrc",
    class: "GENERIC_CREDENTIAL",
    description: "netrc credential store",
  },
  {
    needle: "_netrc",
    class: "GENERIC_CREDENTIAL",
    description: "netrc credential store (Windows)",
  },
  {
    needle: ".git-credentials",
    class: "GENERIC_CREDENTIAL",
    description: "git credential store",
  },
  { needle: ".ssh/id_", class: "SSH_KEY", description: "SSH private key" },
  { needle: "id_rsa", class: "SSH_KEY", description: "SSH private key" },
  { needle: "id_ed25519", class: "SSH_KEY", description: "SSH private key" },
  { needle: ".ssh/", class: "SSH_KEY", description: "SSH configuration directory" },
  {
    needle: ".aws/credentials",
    class: "CLOUD_CREDENTIAL",
    description: "AWS credentials file",
  },
  {
    needle: ".aws/config",
    class: "CLOUD_CREDENTIAL",
    description: "AWS configuration file",
  },
  {
    needle: ".config/gcloud",
    class: "CLOUD_CREDENTIAL",
    description: "Google Cloud credential directory",
  },
  {
    needle: "gcloud/credentials",
    class: "CLOUD_CREDENTIAL",
    description: "Google Cloud credentials",
  },
  {
    needle: ".kube/config",
    class: "CLOUD_CREDENTIAL",
    description: "Kubernetes cluster credentials",
  },
  {
    needle: ".docker/config.json",
    class: "CLOUD_CREDENTIAL",
    description: "Docker registry credentials",
  },
  {
    needle: ".azure/",
    class: "CLOUD_CREDENTIAL",
    description: "Azure CLI credential directory",
  },
  {
    needle: ".bash_history",
    class: "SHELL_HISTORY",
    description: "shell command history",
  },
  {
    needle: ".zsh_history",
    class: "SHELL_HISTORY",
    description: "shell command history",
  },
  { needle: ".sh_history", class: "SHELL_HISTORY", description: "shell command history" },
  {
    needle: ".gnupg",
    class: "GENERIC_CREDENTIAL",
    description: "GnuPG keyring directory",
  },
  {
    needle: "login data",
    class: "BROWSER_OR_WALLET",
    description: "Chromium saved-password database",
  },
  {
    needle: "logins.json",
    class: "BROWSER_OR_WALLET",
    description: "Firefox saved-password store",
  },
  {
    needle: "cookies.sqlite",
    class: "BROWSER_OR_WALLET",
    description: "Firefox cookie store",
  },
  {
    needle: "wallet.dat",
    class: "BROWSER_OR_WALLET",
    description: "cryptocurrency wallet",
  },
  { needle: "keychain", class: "GENERIC_CREDENTIAL", description: "OS keychain" },
];

/**
 * Hosts whose defining property is that anyone can receive data at them with no
 * account, no domain and no attribution: paste sites, chat webhooks, request
 * catchers and tunnels.
 *
 * Legitimate uses exist — CI notification plugins post to chat webhooks — which
 * is why this raises severity rather than producing a verdict.
 */
export const EXFILTRATION_SHAPED_HOSTS: readonly string[] = [
  "pastebin.com",
  "paste.ee",
  "hastebin.com",
  "ghostbin.com",
  "termbin.com",
  "transfer.sh",
  "file.io",
  "0x0.st",
  "anonfiles.com",
  "gofile.io",
  "discord.com/api/webhooks",
  "discordapp.com/api/webhooks",
  "hooks.slack.com",
  "api.telegram.org/bot",
  "webhook.site",
  "requestbin.com",
  "pipedream.net",
  "interact.sh",
  "oast.fun",
  "oast.pro",
  "burpcollaborator.net",
  "ngrok.io",
  "ngrok-free.app",
  "trycloudflare.com",
  "loca.lt",
  "serveo.net",
  "localtunnel.me",
];

/**
 * URL literals that are identifiers rather than destinations. XML and JSON
 * schema namespaces are `http://` strings that nothing ever connects to;
 * reporting them as network destinations is pure noise and would bury the
 * handful of URLs that matter.
 */
export const NON_DESTINATION_URL_PREFIXES: readonly string[] = [
  "http://www.w3.org/",
  "https://www.w3.org/",
  "http://schemas.xmlsoap.org/",
  "http://purl.org/",
  "http://ns.adobe.com/",
  "http://json-schema.org/",
  "https://json-schema.org/",
  "http://www.opengis.net/",
  "http://xml.org/",
  "http://localhost",
  "https://localhost",
  "http://127.0.0.1",
  "http://0.0.0.0",
];

/** Public DNS resolvers, which are legitimate reasons to hardcode an IP. */
export const WELL_KNOWN_RESOLVER_IPS: ReadonlySet<string> = new Set([
  "1.1.1.1",
  "1.0.0.1",
  "8.8.8.8",
  "8.8.4.4",
  "9.9.9.9",
  "208.67.222.222",
  "208.67.220.220",
]);
