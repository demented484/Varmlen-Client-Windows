import { browser } from "$app/environment";
import {
  normalizeSubscriptionUserAgent,
  type SubscriptionUserAgent,
} from "./subscription-user-agent";

export type LogLevel = "debug" | "warn" | "error";

interface Persisted {
  killswitch: boolean;
  allowLan: boolean;
  /** Closing the window hides to the tray (true) vs fully quits (false). */
  closeToTray: boolean;
  /** Verbosity of the Xray VPN log. */
  logLevel: LogLevel;
  /** Identity advertised only while importing/refreshing subscriptions. */
  subscriptionUserAgent: SubscriptionUserAgent;
  subscriptionAutoUpdate: boolean;
}

const KEY = "varmlen.settings";
const DEFAULTS: Persisted = {
  killswitch: true,
  allowLan: true,
  closeToTray: true,
  logLevel: "warn",
  subscriptionUserAgent: "varmlen",
  subscriptionAutoUpdate: true,
};

const LOG_LEVELS: LogLevel[] = ["debug", "warn", "error"];

function load(): Persisted {
  if (!browser) return DEFAULTS;
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<Persisted>;
    return {
      killswitch: parsed.killswitch ?? DEFAULTS.killswitch,
      allowLan: parsed.allowLan ?? DEFAULTS.allowLan,
      closeToTray: parsed.closeToTray ?? DEFAULTS.closeToTray,
      logLevel: LOG_LEVELS.includes(parsed.logLevel as LogLevel)
        ? (parsed.logLevel as LogLevel)
        : DEFAULTS.logLevel,
      subscriptionUserAgent: normalizeSubscriptionUserAgent(
        parsed.subscriptionUserAgent,
      ),
      subscriptionAutoUpdate:
        parsed.subscriptionAutoUpdate ?? DEFAULTS.subscriptionAutoUpdate,
    };
  } catch {
    return DEFAULTS;
  }
}

const _initialSettings = load();

class SettingsStore {
  killswitch = $state(_initialSettings.killswitch);
  allowLan = $state(_initialSettings.allowLan);
  closeToTray = $state(_initialSettings.closeToTray);
  logLevel = $state<LogLevel>(_initialSettings.logLevel);
  subscriptionUserAgent = $state<SubscriptionUserAgent>(
    _initialSettings.subscriptionUserAgent,
  );
  subscriptionAutoUpdate = $state(_initialSettings.subscriptionAutoUpdate);

  private persist(): void {
    if (!browser) return;
    localStorage.setItem(
      KEY,
      JSON.stringify({
        killswitch: this.killswitch,
        allowLan: this.allowLan,
        closeToTray: this.closeToTray,
        logLevel: this.logLevel,
        subscriptionUserAgent: this.subscriptionUserAgent,
        subscriptionAutoUpdate: this.subscriptionAutoUpdate,
      }),
    );
  }

  setKillswitch(v: boolean): void { this.killswitch = v; this.persist(); }
  setAllowLan(v: boolean): void { this.allowLan = v; this.persist(); }
  setCloseToTray(v: boolean): void { this.closeToTray = v; this.persist(); }
  setLogLevel(v: LogLevel): void { this.logLevel = v; this.persist(); }
  setSubscriptionUserAgent(v: SubscriptionUserAgent): void {
    this.subscriptionUserAgent = normalizeSubscriptionUserAgent(v);
    this.persist();
  }
  setSubscriptionAutoUpdate(v: boolean): void {
    this.subscriptionAutoUpdate = v;
    this.persist();
  }
}

export const settings = new SettingsStore();
