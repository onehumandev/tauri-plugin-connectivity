import { invoke } from '@tauri-apps/api/core';

/**
 * Describes the physical or logical transport used to connect to the network.
 *
 * When multiple interfaces are active simultaneously (e.g. WiFi + Cellular),
 * this represents the preferred/primary transport as determined by the OS.
 */
export type ConnectionType = 'wifi' | 'ethernet' | 'cellular' | 'unknown';

/**
 * Information about the current network connection.
 *
 * Combines reachability, cost/constraint flags, and the physical connection type
 * to give callers enough context to make network policy decisions.
 */
export interface ConnectionStatus {

   /** Whether the device has an active network path. */
   connected: boolean;

   /**
    * Whether data usage is billed or limited (e.g. mobile data plans, capped
    * hotspots), or `null` when the platform cannot determine the cost.
    *
    * Platform mapping:
    * - **Windows:** `NetworkCostType` is `Fixed` or `Variable`; `Unknown`
    *   returns `null`
    * - **Linux:** NetworkManager primary device `Metered` is `YES` or
    *   `GUESS_YES`; unknown values and the passive fallback return `null`
    * - **iOS:** `NWPath.isExpensive`
    * - **Android:** absence of `NET_CAPABILITY_NOT_METERED`
    */
   metered: boolean | null;

   /**
    * Whether the connection is constrained — approaching or over its data limit,
    * roaming, or background data usage is restricted, or `null` when the
    * platform cannot determine the constraint state.
    *
    * Platform mapping:
    * - **Windows:** `ConstrainedInternetAccess`, `ApproachingDataLimit`,
    *   `OverDataLimit`, `Roaming`, or `BackgroundDataUsageRestricted`
    * - **Linux:** NetworkManager `Connectivity` is `PORTAL` or `LIMITED`,
    *   primary device is metered, or ModemManager reports cellular roaming;
    *   unknown values and the passive fallback can return `null`
    * - **iOS:** `NWPath.isConstrained` (Low Data Mode)
    * - **Android:** missing `NET_CAPABILITY_VALIDATED`, or Data Saver /
    *   `RESTRICT_BACKGROUND_STATUS` on a metered active network
    */
   constrained: boolean | null;

   /**
    * The physical or logical transport used to connect to the network. When
    * `connected` is `false`, this will be `'unknown'`.
    */
   connectionType: ConnectionType;
}

/**
 * Returns the current network connection status.
 *
 * @returns A promise that resolves with the current {@link ConnectionStatus}.
 * @throws Rejects with a string error when the platform is unsupported or when
 * native status detection fails. Unsupported platforms use the message
 * `connection status detection is not supported on this platform`; backend
 * failures use `connection status detection failed: ...` or
 * `connection status detection failed with native error code <code>: ...`.
 */
export async function connectionStatus(): Promise<ConnectionStatus> {
   return invoke<ConnectionStatus>('plugin:connectivity|connection_status');
}

/**
 * Returns the connection transport classes reported by the platform backend.
 *
 * The result is deduplicated and excludes `'unknown'`. On Apple platforms it
 * contains interfaces available to the current satisfied path, so inactive
 * transports are not listed. Other platforms can report present hardware or
 * currently visible networks.
 * An empty array means detection succeeded but found no supported transports;
 * the promise rejects when detection fails before any supported transport can
 * be recovered. When at least one transport is recovered, the result can be a
 * best-effort partial inventory if another interface cannot be inspected.
 * On Android, transports not declared as `PackageManager` system features are
 * reported only while currently active.
 *
 * @throws Rejects with a string error when the platform is unsupported or when
 * native transport detection fails. Unsupported platforms use the message
 * `supported connection type detection is not supported on this platform`;
 * backend failures use `supported connection type detection failed: ...` or
 * `supported connection type detection failed with native error code <code>: ...`.
 */
export async function supportedConnectionTypes(): Promise<Exclude<ConnectionType, 'unknown'>[]> {
   return invoke<Exclude<ConnectionType, 'unknown'>[]>(
      'plugin:connectivity|supported_connection_types'
   );
}
