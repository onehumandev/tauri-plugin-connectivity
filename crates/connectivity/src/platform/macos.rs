use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use block2::{Block, RcBlock};
use dispatch2::{DispatchQueue, DispatchRetained};
use tracing::warn;

use crate::error::{Error, Result};
use crate::types::{ConnectionStatus, ConnectionType, ConnectionTypes};

// Values mirror Apple's `nw_path_status_t` and `nw_interface_type_t` enums
// from the Network framework headers.
const NW_PATH_STATUS_SATISFIED: i32 = 1;
const NW_INTERFACE_TYPE_WIFI: i32 = 1;
const NW_INTERFACE_TYPE_CELLULAR: i32 = 2;
const NW_INTERFACE_TYPE_WIRED: i32 = 3;

type NwPath = *mut c_void;
type NwPathMonitor = *mut c_void;
type NwInterface = *mut c_void;

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
   fn nw_path_monitor_create() -> NwPathMonitor;
   fn nw_path_monitor_set_queue(monitor: NwPathMonitor, queue: &DispatchQueue);
   fn nw_path_monitor_set_update_handler(
      monitor: NwPathMonitor,
      update_handler: &Block<dyn Fn(NwPath)>,
   );
   fn nw_path_monitor_start(monitor: NwPathMonitor);
   fn nw_path_get_status(path: NwPath) -> i32;
   fn nw_path_is_expensive(path: NwPath) -> bool;
   fn nw_path_is_constrained(path: NwPath) -> bool;
   fn nw_path_enumerate_interfaces(
      path: NwPath,
      enumerate_block: &Block<dyn Fn(NwInterface) -> u8>,
   );
   fn nw_interface_get_type(interface: NwInterface) -> i32;
}

// The monitor is a process-lifetime singleton stored in this `OnceLock`. It is
// intentionally never cancelled or dropped: it lives until the process exits,
// at which point the OS reclaims its resources.
static MONITOR: OnceLock<Option<MacosConnectivityMonitor>> = OnceLock::new();

struct MacosConnectivityMonitor {
   _monitor: NwPathMonitor,
   _queue: DispatchRetained<DispatchQueue>,
   _handler: RcBlock<dyn Fn(NwPath)>,
   cache: Arc<RwLock<Option<CachedConnectivity>>>,
}

/// Snapshot of the connectivity state derived from the latest reported path.
#[derive(Clone)]
struct CachedConnectivity {
   status: ConnectionStatus,
   supported_types: Vec<ConnectionType>,
}

// SAFETY: Rust code only ever reads `cache` (already `Send + Sync`); the
// remaining fields are only used by the Network framework on its own queue,
// and the value lives in a static so it is never dropped.
unsafe impl Send for MacosConnectivityMonitor {}
unsafe impl Sync for MacosConnectivityMonitor {}

/// Returns the connection status last reported by the path monitor.
///
/// The monitor delivers path updates asynchronously on its dispatch queue,
/// starting with an initial update shortly after `nw_path_monitor_start`.
/// Until that first update lands, the cache is empty and this reports disconnected.
/// Either way, re-check at the decision point rather than relying on earlier results.
pub(crate) fn connection_status() -> Result<ConnectionStatus> {
   let monitor = MONITOR.get_or_init(create_monitor);

   monitor
      .as_ref()
      .map(MacosConnectivityMonitor::current_status)
      .ok_or_else(|| Error::DetectionFailed {
         message: String::from("failed to create macOS path monitor"),
         code: None,
      })
}

/// Returns the supported transport classes of the last reported path.
///
/// Until the first path update lands, the cache is empty and this reports an
/// empty inventory, matching the disconnected status reported in that window.
pub(crate) fn supported_connection_types() -> Result<Vec<ConnectionType>> {
   let monitor = MONITOR.get_or_init(create_monitor);

   monitor
      .as_ref()
      .map(MacosConnectivityMonitor::supported_connection_types)
      .ok_or_else(|| Error::SupportedConnectionTypesDetectionFailed {
         message: String::from("failed to create macOS path monitor"),
         code: None,
      })
}

fn create_monitor() -> Option<MacosConnectivityMonitor> {
   let monitor = unsafe { nw_path_monitor_create() };
   if monitor.is_null() {
      warn!("failed to create macOS path monitor");
      return None;
   }

   let queue = DispatchQueue::new("tauri.plugin.connectivity.path", None);
   let cache = Arc::new(RwLock::new(None));
   let handler_cache = Arc::clone(&cache);
   let handler = RcBlock::new(move |path: NwPath| match handler_cache.write() {
      Ok(mut cache) => {
         *cache = Some(read_connectivity(path));
      }
      Err(error) => {
         warn!(%error, "failed to update macOS connectivity cache");
      }
   });

   unsafe {
      nw_path_monitor_set_queue(monitor, &queue);
      nw_path_monitor_set_update_handler(monitor, &handler);
      nw_path_monitor_start(monitor);
   }

   Some(MacosConnectivityMonitor {
      _monitor: monitor,
      _queue: queue,
      _handler: handler,
      cache,
   })
}

impl MacosConnectivityMonitor {
   fn current_status(&self) -> ConnectionStatus {
      self
         .cache
         .read()
         .map(|cache| cached_status(cache.clone()))
         .unwrap_or_else(|error| {
            warn!(%error, "failed to read macOS connection status cache");
            ConnectionStatus::disconnected()
         })
   }

   fn supported_connection_types(&self) -> Vec<ConnectionType> {
      self
         .cache
         .read()
         .map(|cache| cached_supported_types(cache.clone()))
         .unwrap_or_else(|error| {
            warn!(%error, "failed to read macOS connectivity cache");
            Vec::new()
         })
   }
}

fn cached_status(cache: Option<CachedConnectivity>) -> ConnectionStatus {
   cache
      .map(|cache| cache.status)
      .unwrap_or_else(ConnectionStatus::disconnected)
}

fn cached_supported_types(cache: Option<CachedConnectivity>) -> Vec<ConnectionType> {
   cache.map(|cache| cache.supported_types).unwrap_or_default()
}

/// Other interface types (loopback, `nw_interface_type_other`) intentionally
/// map to `Unknown`: the plugin only distinguishes transports callers can act on.
fn map_interface_type(interface_type: i32) -> ConnectionType {
   match interface_type {
      NW_INTERFACE_TYPE_WIFI => ConnectionType::Wifi,
      NW_INTERFACE_TYPE_WIRED => ConnectionType::Ethernet,
      NW_INTERFACE_TYPE_CELLULAR => ConnectionType::Cellular,
      _ => ConnectionType::Unknown,
   }
}

#[derive(Default)]
struct ResolvedConnectionTypes {
   primary: Option<ConnectionType>,
   supported: ConnectionTypes,
}

impl ResolvedConnectionTypes {
   fn record(&mut self, connection_type: ConnectionType) {
      if self.primary.is_none() {
         self.primary = Some(connection_type);
      }

      self.supported.insert(connection_type);
   }

   fn into_parts(self) -> (ConnectionType, Vec<ConnectionType>) {
      (
         self.primary.unwrap_or(ConnectionType::Unknown),
         self.supported.into_vec(),
      )
   }
}

fn resolve_connection_types(path: NwPath) -> (ConnectionType, Vec<ConnectionType>) {
   // Enumeration is synchronous, but the block must be `'static`, so the value
   // is shared back out through an `Arc`. The lock can only be poisoned by a
   // panic while held, which cannot happen here, so poison is recovered rather
   // than treated as an error.
   let resolved_types = Arc::new(Mutex::new(ResolvedConnectionTypes {
      primary: None,
      supported: ConnectionTypes::new(),
   }));
   let resolved_types_for_block = Arc::clone(&resolved_types);
   let block = RcBlock::new(move |interface: NwInterface| -> u8 {
      let connection_type = map_interface_type(unsafe { nw_interface_get_type(interface) });
      let mut resolved_types = resolved_types_for_block
         .lock()
         .unwrap_or_else(|poisoned| poisoned.into_inner());

      // Path interfaces are enumerated in order of preference, so the first
      // interface is the OS-selected primary transport.
      resolved_types.record(connection_type);

      1
   });

   unsafe {
      nw_path_enumerate_interfaces(path, &block);
   }

   let mut resolved_types = resolved_types
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());

   std::mem::take(&mut *resolved_types).into_parts()
}

/// Apple reports path availability, not whether a specific request will succeed.
///
/// We only treat `nw_path_status_satisfied` as `connected = true`, because that
/// is the state where the path is currently usable for sending and receiving
/// data.
///
/// We still treat `nw_path_status_satisfiable` as disconnected. Apple describes
/// that state as a path that is not currently available, even though a future
/// connection attempt may activate it.
///
/// References:
/// - `nw_path_status_satisfied`: <https://developer.apple.com/documentation/network/nw_path_status_satisfied>
/// - `nw_path_status_satisfiable`: <https://developer.apple.com/documentation/network/nw_path_status_satisfiable>
/// - `nw_path_status_t`: <https://developer.apple.com/documentation/network/nw_path_status_t>
fn is_connected_status(status: i32) -> bool {
   status == NW_PATH_STATUS_SATISFIED
}

fn read_connectivity(path: NwPath) -> CachedConnectivity {
   let connected = is_connected_status(unsafe { nw_path_get_status(path) });
   if !connected {
      return CachedConnectivity {
         status: assemble_status(false, false, false, ConnectionType::Unknown),
         supported_types: Vec::new(),
      };
   }

   let metered = unsafe { nw_path_is_expensive(path) };
   let constrained = unsafe { nw_path_is_constrained(path) };
   let (connection_type, supported_types) = resolve_connection_types(path);

   CachedConnectivity {
      status: assemble_status(true, metered, constrained, connection_type),
      supported_types,
   }
}

fn assemble_status(
   connected: bool,
   metered: bool,
   constrained: bool,
   connection_type: ConnectionType,
) -> ConnectionStatus {
   if !connected {
      return ConnectionStatus::disconnected();
   }

   ConnectionStatus {
      connected: true,
      metered: Some(metered),
      constrained: Some(constrained),
      connection_type,
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn maps_interface_type_to_connection_type() {
      assert_eq!(
         map_interface_type(NW_INTERFACE_TYPE_WIFI),
         ConnectionType::Wifi
      );
      assert_eq!(
         map_interface_type(NW_INTERFACE_TYPE_WIRED),
         ConnectionType::Ethernet
      );
      assert_eq!(
         map_interface_type(NW_INTERFACE_TYPE_CELLULAR),
         ConnectionType::Cellular
      );
      assert_eq!(map_interface_type(0), ConnectionType::Unknown);
      assert_eq!(map_interface_type(4), ConnectionType::Unknown);
   }

   #[test]
   fn disconnected_status_has_unknown_connection_type() {
      assert_eq!(
         ConnectionStatus::disconnected().connection_type,
         ConnectionType::Unknown
      );
   }

   #[test]
   fn missing_cached_status_defaults_to_disconnected() {
      assert_eq!(cached_status(None), ConnectionStatus::disconnected());
   }

   #[test]
   fn missing_cached_supported_types_defaults_to_empty() {
      assert!(cached_supported_types(None).is_empty());
   }

   #[test]
   fn cached_supported_types_returns_cached_inventory() {
      let cache = CachedConnectivity {
         status: ConnectionStatus::disconnected(),
         supported_types: vec![ConnectionType::Wifi, ConnectionType::Ethernet],
      };

      assert_eq!(
         cached_supported_types(Some(cache)),
         vec![ConnectionType::Wifi, ConnectionType::Ethernet]
      );
   }

   #[test]
   fn resolved_connection_types_preserves_first_type_as_primary() {
      let mut resolved_types = ResolvedConnectionTypes::default();

      resolved_types.record(ConnectionType::Ethernet);
      resolved_types.record(ConnectionType::Wifi);

      assert_eq!(
         resolved_types.into_parts(),
         (
            ConnectionType::Ethernet,
            vec![ConnectionType::Wifi, ConnectionType::Ethernet],
         )
      );
   }

   #[test]
   fn resolved_connection_types_accumulates_and_deduplicates_supported_types() {
      let mut resolved_types = ResolvedConnectionTypes::default();

      resolved_types.record(ConnectionType::Ethernet);
      resolved_types.record(ConnectionType::Wifi);
      resolved_types.record(ConnectionType::Ethernet);

      let (_, supported_types) = resolved_types.into_parts();

      assert_eq!(
         supported_types,
         vec![ConnectionType::Wifi, ConnectionType::Ethernet]
      );
   }

   #[test]
   fn resolved_connection_types_keeps_unknown_primary_but_omits_it_from_supported() {
      let mut resolved_types = ResolvedConnectionTypes::default();

      resolved_types.record(ConnectionType::Unknown);
      resolved_types.record(ConnectionType::Wifi);

      assert_eq!(
         resolved_types.into_parts(),
         (ConnectionType::Unknown, vec![ConnectionType::Wifi])
      );
   }

   #[test]
   fn resolved_connection_types_defaults_when_empty() {
      assert_eq!(
         ResolvedConnectionTypes::default().into_parts(),
         (ConnectionType::Unknown, Vec::new())
      );
   }

   #[test]
   fn disconnected_assembled_status_uses_disconnected_defaults() {
      assert_eq!(
         assemble_status(false, true, true, ConnectionType::Wifi),
         ConnectionStatus::disconnected()
      );
   }

   #[test]
   fn connected_assembled_status_preserves_policy_flags_and_connection_type() {
      assert_eq!(
         assemble_status(true, true, true, ConnectionType::Cellular),
         ConnectionStatus {
            connected: true,
            metered: Some(true),
            constrained: Some(true),
            connection_type: ConnectionType::Cellular,
         }
      );
   }

   #[test]
   fn only_satisfied_status_is_connected() {
      assert!(is_connected_status(NW_PATH_STATUS_SATISFIED));

      for status in [0, 2, 3, i32::MIN, i32::MAX] {
         assert!(!is_connected_status(status));
      }
   }
}
