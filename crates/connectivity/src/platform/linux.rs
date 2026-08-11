use std::fs;
use std::path::Path;
use std::time::Duration;

use tracing::{debug, warn};
use zbus::blocking::connection::Builder as ConnectionBuilder;
use zbus::blocking::fdo::DBusProxy;
use zbus::blocking::proxy::Builder as ProxyBuilder;
use zbus::blocking::{Connection, Proxy};
use zbus::names::BusName;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use crate::error::{Error, Result};
use crate::types::{ConnectionStatus, ConnectionType, ConnectionTypes};

// These local D-Bus calls read cached service state and normally complete within
// milliseconds. Bound each call so a stalled service cannot occupy the blocking
// thread for long before the query uses its fallback. This does not bound the
// initial socket connect/Hello handshake or the total Linux status query.
const DBUS_METHOD_TIMEOUT: Duration = Duration::from_millis(500);

const DBUS_SERVICE: &str = "org.freedesktop.DBus";

// NetworkManager exposes cached root properties for connection state. We read
// `Connectivity` instead of calling `CheckConnectivity()` because that method
// can issue a connectivity probe.
// https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/gdbus-org.freedesktop.NetworkManager.html
const NETWORK_MANAGER_SERVICE: &str = "org.freedesktop.NetworkManager";
const NETWORK_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const NETWORK_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";

// The primary active connection points at the NetworkManager devices that carry
// it; device properties provide transport, metered state, and the ModemManager
// object path for modem devices.
// https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/gdbus-org.freedesktop.NetworkManager.Connection.Active.html
// https://www.networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html
const NETWORK_MANAGER_ACTIVE_CONNECTION_INTERFACE: &str =
   "org.freedesktop.NetworkManager.Connection.Active";
const NETWORK_MANAGER_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";

// ModemManager is only used for cellular roaming. A missing service or 3GPP
// interface, an unknown registration state, and read errors leave the roaming
// signal unknown.
// https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Modem3gpp.html
const MODEM_MANAGER_SERVICE: &str = "org.freedesktop.ModemManager1";
const MODEM_MANAGER_MODEM_PREFIX: &str = "/org/freedesktop/ModemManager1/Modem/";
const MODEM_MANAGER_3GPP_INTERFACE: &str = "org.freedesktop.ModemManager1.Modem.Modem3gpp";

// NetworkManager D-Bus enum values
// https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-dbus-types.html
const NM_CONNECTIVITY_NONE: u32 = 1;
const NM_CONNECTIVITY_PORTAL: u32 = 2;
const NM_CONNECTIVITY_LIMITED: u32 = 3;
const NM_CONNECTIVITY_FULL: u32 = 4;

const NM_STATE_CONNECTED_GLOBAL: u32 = 70;

const NM_DEVICE_TYPE_ETHERNET: u32 = 1;
const NM_DEVICE_TYPE_WIFI: u32 = 2;
const NM_DEVICE_TYPE_MODEM: u32 = 8;

const NM_METERED_UNKNOWN: u32 = 0;
const NM_METERED_YES: u32 = 1;
const NM_METERED_NO: u32 = 2;
const NM_METERED_GUESS_YES: u32 = 3;
const NM_METERED_GUESS_NO: u32 = 4;

const MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN: u32 = 4;
const MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING: u32 = 5;
const MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_SMS_ONLY: u32 = 7;
const MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_CSFB_NOT_PREFERRED: u32 = 10;
const MM_MODEM_3GPP_REGISTRATION_STATE_ATTACHED_RLOS: u32 = 11;

// Passive fallback inputs. This path intentionally avoids DNS, ping, HTTP, or
// any other active reachability probe.
const PROC_NET_ROUTE: &str = "/proc/net/route";
const PROC_NET_IPV6_ROUTE: &str = "/proc/net/ipv6_route";
const SYS_CLASS_NET: &str = "/sys/class/net";
const LINUX_ARPHRD_ETHER: u32 = 1;
const LINUX_ROUTE_FLAG_UP: u32 = 0x1;
const IPV4_DEFAULT_DESTINATION: &str = "00000000";
const IPV6_DEFAULT_DESTINATION: &str = "00000000000000000000000000000000";
const IPV6_DEFAULT_PREFIX_LEN: &str = "00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectedState {
   Connected,
   Constrained,
   Disconnected,
   Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionDetails {
   metered: Option<bool>,
   roaming: Option<bool>,
   connection_type: ConnectionType,
}

impl Default for ConnectionDetails {
   fn default() -> Self {
      Self {
         metered: None,
         roaming: None,
         connection_type: ConnectionType::Unknown,
      }
   }
}

/// Returns the current Linux network connection status.
///
/// NetworkManager is preferred when available because it exposes cached
/// connectivity, primary-route, transport, and metered state over D-Bus. Systems
/// without NetworkManager fall back to passive kernel state only.
pub(crate) fn connection_status() -> Result<ConnectionStatus> {
   debug!("querying Linux connection status");

   let connection = match system_bus_connection() {
      Ok(connection) => {
         debug!("connected to Linux system D-Bus");
         connection
      }
      Err(error) => {
         warn!(%error, "failed to connect to Linux system bus; using passive fallback");
         return Ok(fallback_connection_status());
      }
   };

   match service_has_owner(&connection, NETWORK_MANAGER_SERVICE) {
      Ok(true) => {
         debug!("NetworkManager service is present");

         match network_manager_connection_status(&connection) {
            Ok(status) => {
               debug!(
                  ?status,
                  "resolved Linux connection status via NetworkManager"
               );
               Ok(status)
            }
            Err(error) => {
               warn!(%error, "failed to query NetworkManager; using passive fallback");
               Ok(fallback_connection_status())
            }
         }
      }
      Ok(false) => {
         debug!("NetworkManager service is not present; using passive fallback");
         Ok(fallback_connection_status())
      }
      Err(error) => {
         warn!(%error, "failed to probe NetworkManager service; using passive fallback");
         Ok(fallback_connection_status())
      }
   }
}

/// Returns the supported physical connection transport classes.
pub(crate) fn supported_connection_types() -> Result<Vec<ConnectionType>> {
   debug!("querying Linux supported connection types");

   // Prefer NetworkManager's realized `Devices` list. Its D-Bus docs describe
   // `Devices` as the network devices currently known to NetworkManager, while
   // `AllDevices` can include placeholders that do not correspond to real,
   // present hardware:
   // https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html
   let connection = match system_bus_connection() {
      Ok(connection) => connection,
      Err(error) => {
         warn!(%error, "failed to connect to Linux system bus; using sysfs fallback");
         return supported_types_from_sysfs(Path::new(SYS_CLASS_NET));
      }
   };

   match service_has_owner(&connection, NETWORK_MANAGER_SERVICE) {
      Ok(true) => match network_manager_supported_connection_types(&connection) {
         Ok(connection_types) => Ok(connection_types),
         Err(error) => {
            warn!(%error, "failed to query NetworkManager devices; using sysfs fallback");
            supported_types_from_sysfs(Path::new(SYS_CLASS_NET))
         }
      },
      Ok(false) => supported_types_from_sysfs(Path::new(SYS_CLASS_NET)),
      Err(error) => {
         warn!(%error, "failed to probe NetworkManager service; using sysfs fallback");
         supported_types_from_sysfs(Path::new(SYS_CLASS_NET))
      }
   }
}

fn network_manager_supported_connection_types(
   connection: &Connection,
) -> zbus::Result<Vec<ConnectionType>> {
   let manager = dbus_proxy(
      connection,
      NETWORK_MANAGER_SERVICE,
      NETWORK_MANAGER_PATH,
      NETWORK_MANAGER_INTERFACE,
   )?;
   let devices = manager.get_property::<Vec<OwnedObjectPath>>("Devices")?;

   collect_supported_connection_types_from_devices(devices, |device| {
      // DeviceType is the NetworkManager transport enum. Values used below are
      // from the NetworkManager D-Bus type reference:
      // https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-dbus-types.html
      let device_proxy = dbus_proxy(
         connection,
         NETWORK_MANAGER_SERVICE,
         device.as_str(),
         NETWORK_MANAGER_DEVICE_INTERFACE,
      )?;
      device_proxy.get_property::<u32>("DeviceType")
   })
}

fn system_bus_connection() -> zbus::Result<Connection> {
   ConnectionBuilder::system()?
      .method_timeout(DBUS_METHOD_TIMEOUT)
      .build()
}

fn network_manager_connection_status(connection: &Connection) -> zbus::Result<ConnectionStatus> {
   let manager = dbus_proxy(
      connection,
      NETWORK_MANAGER_SERVICE,
      NETWORK_MANAGER_PATH,
      NETWORK_MANAGER_INTERFACE,
   )?;

   // `Connectivity` is a cached property. `FULL` maps to full connectivity,
   // `PORTAL` and `LIMITED` map to connected but constrained, and `UNKNOWN`
   // falls back to NM's broader networking state.
   let connectivity = manager.get_property::<u32>("Connectivity")?;
   debug!(connectivity, "queried NetworkManager connectivity state");

   let connectivity_state = match map_connectivity(connectivity) {
      ConnectedState::Unknown => {
         let state = manager.get_property::<u32>("State")?;
         debug!(
            connectivity,
            state, "NetworkManager connectivity is unknown; falling back to state"
         );
         connectivity_state_from_global_state(state)
      }
      connectivity_state => connectivity_state,
   };
   let connected = matches!(
      connectivity_state,
      ConnectedState::Connected | ConnectedState::Constrained
   );

   if !connected {
      debug!(
         connectivity,
         "NetworkManager connectivity does not indicate active internet access"
      );
      return Ok(ConnectionStatus::disconnected());
   }

   let details = match primary_connection_details(connection, &manager) {
      Ok(details) => details,
      Err(error) => {
         warn!(%error, "failed to resolve Linux primary connection details; policy state is unknown");
         ConnectionDetails::default()
      }
   };

   Ok(ConnectionStatus {
      connected: true,
      metered: details.metered,
      constrained: constrained_status(connectivity_state, details.metered, details.roaming),
      connection_type: details.connection_type,
   })
}

fn primary_connection_details(
   connection: &Connection,
   manager: &Proxy<'_>,
) -> zbus::Result<ConnectionDetails> {
   // NetworkManager chooses the primary connection for the default route. Its
   // active connection object is the stable way to find the devices that should
   // drive transport and metered decisions.
   let primary_connection = manager.get_property::<OwnedObjectPath>("PrimaryConnection")?;
   debug!(
      primary_connection = %primary_connection.as_str(),
      "queried NetworkManager primary connection"
   );

   if is_root_path(&primary_connection) {
      warn!("NetworkManager returned no primary connection; policy state is unknown");
      return Ok(ConnectionDetails::default());
   }

   let active_connection = dbus_proxy(
      connection,
      NETWORK_MANAGER_SERVICE,
      primary_connection.as_str(),
      NETWORK_MANAGER_ACTIVE_CONNECTION_INTERFACE,
   )?;
   let devices = active_connection.get_property::<Vec<OwnedObjectPath>>("Devices")?;
   debug!(
      device_count = devices.len(),
      primary_connection = %primary_connection.as_str(),
      "queried NetworkManager primary connection devices"
   );

   if devices.is_empty() {
      warn!("NetworkManager primary connection has no devices; policy state is unknown");
      return Ok(ConnectionDetails::default());
   }

   let mut details = ConnectionDetails::default();
   let mut read_any_device = false;
   let mut metered_states = Vec::with_capacity(devices.len());
   let mut roaming_states = Vec::with_capacity(devices.len());

   for device in devices {
      match device_details(connection, &device) {
         Ok(device_details) => {
            read_any_device = true;
            metered_states.push(device_details.metered);
            roaming_states.push(device_details.roaming);
            if details.connection_type == ConnectionType::Unknown {
               details.connection_type = device_details.connection_type;
            }

            debug!(
               device = %device.as_str(),
               metered = ?device_details.metered,
               roaming = ?device_details.roaming,
               connection_type = ?device_details.connection_type,
               "resolved NetworkManager device details"
            );
         }
         Err(error) => {
            warn!(%error, device = %device.as_str(), "failed to read NetworkManager device");
            metered_states.push(None);
            roaming_states.push(None);
         }
      }
   }

   if !read_any_device {
      warn!(
         "failed to read any NetworkManager primary connection devices; policy state is unknown"
      );
   }

   details.metered = combine_policy_states(metered_states);
   details.roaming = combine_policy_states(roaming_states);

   Ok(details)
}

fn device_details(
   connection: &Connection,
   device: &OwnedObjectPath,
) -> zbus::Result<ConnectionDetails> {
   let device_proxy = dbus_proxy(
      connection,
      NETWORK_MANAGER_SERVICE,
      device.as_str(),
      NETWORK_MANAGER_DEVICE_INTERFACE,
   )?;

   // DeviceType gives the transport class; Metered lives on the device, not on
   // the active connection.
   let device_type = device_proxy.get_property::<u32>("DeviceType")?;
   let connection_type = map_device_type(device_type);
   debug!(
      device = %device.as_str(),
      device_type,
      connection_type = ?connection_type,
      "queried NetworkManager device type"
   );

   let metered = match device_proxy.get_property::<u32>("Metered") {
      Ok(metered) => {
         let metered_status = metered_status(metered);
         debug!(
            device = %device.as_str(),
            metered,
            metered_status = ?metered_status,
            "queried NetworkManager device metered state"
         );
         metered_status
      }
      Err(error) => {
         warn!(%error, device = %device.as_str(), "failed to read NetworkManager device metered state; metering is unknown");
         None
      }
   };
   let roaming = connection_type_roaming_status(connection_type, || {
      modem_is_roaming(connection, &device_proxy)
   });

   Ok(ConnectionDetails {
      metered,
      roaming,
      connection_type,
   })
}

fn connection_type_roaming_status(
   connection_type: ConnectionType,
   cellular_status: impl FnOnce() -> Option<bool>,
) -> Option<bool> {
   if connection_type == ConnectionType::Cellular {
      cellular_status()
   } else {
      // NetworkManager's modem type maps to Cellular. Every other mapped or
      // unknown transport is therefore definitively outside roaming policy.
      Some(false)
   }
}

fn modem_is_roaming(connection: &Connection, device_proxy: &Proxy<'_>) -> Option<bool> {
   // NM modem devices expose a `Udi` that usually points at the corresponding
   // ModemManager object. Only that object can tell us whether the cellular
   // registration state is roaming.
   match service_has_owner(connection, MODEM_MANAGER_SERVICE) {
      Ok(true) => {}
      Ok(false) => {
         debug!("ModemManager service is not present; roaming is unknown");
         return None;
      }
      Err(error) => {
         warn!(%error, "failed to probe ModemManager service; roaming is unknown");
         return None;
      }
   }

   let udi = match device_proxy.get_property::<String>("Udi") {
      Ok(udi) => {
         debug!(udi, "queried NetworkManager modem Udi");
         udi
      }
      Err(error) => {
         warn!(%error, "failed to read NetworkManager modem Udi; roaming is unknown");
         return None;
      }
   };

   if !is_modem_manager_modem_path(&udi) {
      debug!(
         udi,
         "NetworkManager modem Udi is not a ModemManager modem path"
      );
      return None;
   }

   let modem_path = match ObjectPath::try_from(udi.as_str()) {
      Ok(path) => path,
      Err(error) => {
         warn!(%error, udi, "NetworkManager modem Udi is not a valid D-Bus object path");
         return None;
      }
   };

   let modem = match dbus_proxy(
      connection,
      MODEM_MANAGER_SERVICE,
      modem_path.as_str(),
      MODEM_MANAGER_3GPP_INTERFACE,
   ) {
      Ok(modem) => modem,
      Err(error) => {
         warn!(%error, "failed to create ModemManager proxy; roaming is unknown");
         return None;
      }
   };

   match modem.get_property::<u32>("RegistrationState") {
      Ok(registration_state) => {
         let roaming = roaming_status(registration_state);
         debug!(
            registration_state,
            roaming = ?roaming,
            "queried ModemManager 3GPP registration state"
         );
         roaming
      }
      Err(error) => {
         warn!(%error, "failed to read ModemManager 3GPP registration state; roaming is unknown");
         None
      }
   }
}

fn dbus_proxy<'a>(
   connection: &'a Connection,
   destination: &'a str,
   path: &'a str,
   interface: &'a str,
) -> zbus::Result<Proxy<'a>> {
   ProxyBuilder::new(connection)
      .destination(destination)?
      .path(path)?
      .interface(interface)?
      .cache_properties(CacheProperties::No)
      .build()
}

fn service_has_owner(connection: &Connection, service: &str) -> zbus::Result<bool> {
   let proxy = DBusProxy::builder(connection)
      .destination(DBUS_SERVICE)?
      .cache_properties(CacheProperties::No)
      .build()?;
   let service_name = BusName::try_from(service)?;

   Ok(proxy.name_has_owner(service_name)?)
}

fn fallback_connection_status() -> ConnectionStatus {
   // Systems that do not run NetworkManager still commonly expose kernel route
   // tables through /proc. An up, non-loopback default route is the strongest
   // passive signal available without probing the network.
   let ipv4_route_table = match fs::read_to_string(PROC_NET_ROUTE) {
      Ok(route_table) => route_table,
      Err(error) => {
         warn!(%error, "failed to read Linux IPv4 route table");
         String::new()
      }
   };
   let ipv6_route_table = match fs::read_to_string(PROC_NET_IPV6_ROUTE) {
      Ok(route_table) => route_table,
      Err(error) => {
         warn!(%error, "failed to read Linux IPv6 route table");
         String::new()
      }
   };

   fallback_connection_status_from_routes(
      &ipv4_route_table,
      &ipv6_route_table,
      Path::new(SYS_CLASS_NET),
   )
}

fn fallback_connection_status_from_routes(
   ipv4_route_table: &str,
   ipv6_route_table: &str,
   sys_class_net: &Path,
) -> ConnectionStatus {
   let Some(iface) = default_ipv4_route_interface(ipv4_route_table)
      .or_else(|| default_ipv6_route_interface(ipv6_route_table))
   else {
      debug!("Linux route table does not contain an up, non-loopback default route");
      return ConnectionStatus::disconnected();
   };

   let connection_type = infer_transport_from_sysfs(sys_class_net, &iface);
   let status = ConnectionStatus {
      connected: true,
      metered: None,
      constrained: None,
      connection_type,
   };

   debug!(
      iface,
      connection_type = ?status.connection_type,
      "resolved Linux connection status via passive fallback without cost information"
   );

   status
}

fn map_connectivity(connectivity: u32) -> ConnectedState {
   match connectivity {
      NM_CONNECTIVITY_FULL => ConnectedState::Connected,
      NM_CONNECTIVITY_PORTAL | NM_CONNECTIVITY_LIMITED => ConnectedState::Constrained,
      NM_CONNECTIVITY_NONE => ConnectedState::Disconnected,
      _ => ConnectedState::Unknown,
   }
}

fn has_global_connectivity(state: u32) -> bool {
   state == NM_STATE_CONNECTED_GLOBAL
}

fn connectivity_state_from_global_state(state: u32) -> ConnectedState {
   if has_global_connectivity(state) {
      ConnectedState::Connected
   } else {
      ConnectedState::Disconnected
   }
}

fn map_device_type(device_type: u32) -> ConnectionType {
   match device_type {
      NM_DEVICE_TYPE_ETHERNET => ConnectionType::Ethernet,
      NM_DEVICE_TYPE_WIFI => ConnectionType::Wifi,
      NM_DEVICE_TYPE_MODEM => ConnectionType::Cellular,
      _ => ConnectionType::Unknown,
   }
}

fn collect_supported_connection_types(
   device_types: impl IntoIterator<Item = u32>,
) -> Vec<ConnectionType> {
   let mut connection_types = ConnectionTypes::new();

   for device_type in device_types {
      connection_types.insert(map_device_type(device_type));
   }

   connection_types.into_vec()
}

fn collect_supported_connection_types_from_devices<E>(
   devices: impl IntoIterator<Item = OwnedObjectPath>,
   mut read_device_type: impl FnMut(&OwnedObjectPath) -> std::result::Result<u32, E>,
) -> std::result::Result<Vec<ConnectionType>, E>
where
   E: std::fmt::Display,
{
   let mut device_types = Vec::new();
   let mut first_error = None;

   for device in devices {
      match read_device_type(&device) {
         Ok(device_type) => {
            debug!(
               device = %device.as_str(),
               device_type,
               "queried NetworkManager supported device type"
            );
            device_types.push(device_type);
         }
         Err(error) => {
            warn!(%error, device = %device.as_str(), "failed to read NetworkManager device type");
            first_error.get_or_insert(error);
         }
      }
   }

   let connection_types = collect_supported_connection_types(device_types);

   if connection_types.is_empty()
      && let Some(error) = first_error
   {
      return Err(error);
   }

   Ok(connection_types)
}

fn metered_status(metered: u32) -> Option<bool> {
   if metered == NM_METERED_UNKNOWN {
      return None;
   }

   match metered {
      NM_METERED_YES | NM_METERED_GUESS_YES => Some(true),
      NM_METERED_NO | NM_METERED_GUESS_NO => Some(false),
      _ => None,
   }
}

fn constrained_status(
   connectivity_state: ConnectedState,
   metered: Option<bool>,
   roaming: Option<bool>,
) -> Option<bool> {
   // NetworkManager does not expose a separate background-data policy signal.
   // Treat an explicitly or guessed metered primary device as constrained so
   // callers can avoid discretionary data use on Linux.
   let connectivity_constrained = match connectivity_state {
      ConnectedState::Constrained => Some(true),
      ConnectedState::Connected | ConnectedState::Disconnected => Some(false),
      ConnectedState::Unknown => None,
   };

   combine_policy_states([connectivity_constrained, metered, roaming])
}

/// Combines independent policy signals without losing uncertainty. A confirmed
/// restriction wins, but a safe result requires every signal to be known false.
fn combine_policy_states(states: impl IntoIterator<Item = Option<bool>>) -> Option<bool> {
   let mut saw_known_state = false;
   let mut all_states_known = true;

   for state in states {
      match state {
         Some(true) => return Some(true),
         Some(false) => saw_known_state = true,
         None => all_states_known = false,
      }
   }

   (saw_known_state && all_states_known).then_some(false)
}

fn roaming_status(registration_state: u32) -> Option<bool> {
   match registration_state {
      MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN => None,
      MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING
      | MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_SMS_ONLY
      | MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_CSFB_NOT_PREFERRED => Some(true),
      0..=MM_MODEM_3GPP_REGISTRATION_STATE_ATTACHED_RLOS => Some(false),
      _ => None,
   }
}

fn is_modem_manager_modem_path(path: &str) -> bool {
   path.starts_with(MODEM_MANAGER_MODEM_PREFIX) && ObjectPath::try_from(path).is_ok()
}

fn is_root_path(path: &OwnedObjectPath) -> bool {
   path.as_str() == "/"
}

fn default_ipv4_route_interface(route_table: &str) -> Option<String> {
   route_table.lines().skip(1).find_map(|line| {
      let fields: Vec<_> = line.split_whitespace().collect();

      if fields.len() < 4 {
         return None;
      }

      let iface = fields[0];
      let destination = fields[1];
      let flags = fields[3];

      if destination == IPV4_DEFAULT_DESTINATION && iface != "lo" && route_is_up(flags) {
         Some(iface.to_owned())
      } else {
         None
      }
   })
}

fn default_ipv6_route_interface(route_table: &str) -> Option<String> {
   route_table.lines().find_map(|line| {
      let fields: Vec<_> = line.split_whitespace().collect();

      if fields.len() < 10 {
         return None;
      }

      let destination = fields[0];
      let prefix_len = fields[1];
      let flags = fields[8];
      let iface = fields[9];

      if destination == IPV6_DEFAULT_DESTINATION
         && prefix_len == IPV6_DEFAULT_PREFIX_LEN
         && iface != "lo"
         && route_is_up(flags)
      {
         Some(iface.to_owned())
      } else {
         None
      }
   })
}

fn route_is_up(flags: &str) -> bool {
   u32::from_str_radix(flags, 16).is_ok_and(|flags| flags & LINUX_ROUTE_FLAG_UP != 0)
}

fn infer_transport_from_sysfs(sys_class_net: &Path, iface: &str) -> ConnectionType {
   match try_infer_transport_from_sysfs(sys_class_net, iface) {
      Ok(connection_type) => connection_type,
      Err(error) => {
         warn!(message = %error.message, iface, "failed to classify sysfs fallback interface");
         ConnectionType::Unknown
      }
   }
}

struct SysfsTransportError {
   message: String,
   code: Option<i32>,
}

fn try_infer_transport_from_sysfs(
   sys_class_net: &Path,
   iface: &str,
) -> std::result::Result<ConnectionType, SysfsTransportError> {
   let interface_path = sys_class_net.join(iface);

   if has_wifi_marker(&interface_path) {
      debug!(iface, "sysfs classified fallback interface as Wi-Fi");
      return Ok(ConnectionType::Wifi);
   }

   if has_wwan_marker(&interface_path) {
      debug!(iface, "sysfs classified fallback interface as cellular");
      return Ok(ConnectionType::Cellular);
   }

   let type_path = interface_path.join("type");
   let interface_type = fs::read_to_string(&type_path).map_err(|error| SysfsTransportError {
      message: format!(
         "failed to read Linux sysfs interface type at {}: {error}",
         type_path.display()
      ),
      code: error.raw_os_error(),
   })?;
   let interface_type =
      interface_type
         .trim()
         .parse::<u32>()
         .map_err(|error| SysfsTransportError {
            message: format!(
               "failed to parse Linux sysfs interface type at {}: {error}",
               type_path.display()
            ),
            code: None,
         })?;

   if interface_type == LINUX_ARPHRD_ETHER {
      debug!(iface, "sysfs classified fallback interface as Ethernet");
      return Ok(ConnectionType::Ethernet);
   }

   debug!(iface, "sysfs could not classify fallback interface");
   Ok(ConnectionType::Unknown)
}

fn supported_types_from_sysfs(sys_class_net: &Path) -> Result<Vec<ConnectionType>> {
   // `/sys/class/net` is the kernel's sysfs view of present network interfaces.
   // This fallback is intentionally passive, matching the status fallback above:
   // https://docs.kernel.org/networking/net-sysfs.html
   let entries = fs::read_dir(sys_class_net).map_err(|error| {
      Error::SupportedConnectionTypesDetectionFailed {
         message: format!(
            "failed to read Linux sysfs network interfaces at {}: {error}",
            sys_class_net.display()
         ),
         code: error.raw_os_error(),
      }
   })?;

   let mut connection_types = ConnectionTypes::new();
   let mut first_error = None;

   for entry in entries {
      let entry = match entry {
         Ok(entry) => entry,
         Err(error) => {
            let error = SysfsTransportError {
               message: format!(
                  "failed to enumerate Linux sysfs network interfaces at {}: {error}",
                  sys_class_net.display()
               ),
               code: error.raw_os_error(),
            };

            warn!(message = %error.message, "failed to enumerate supported sysfs interface");
            first_error.get_or_insert(error);
            continue;
         }
      };
      let iface = entry.file_name();
      let iface = iface.to_string_lossy();

      if iface == "lo" || is_virtual_sysfs_interface(&entry.path()) {
         continue;
      }

      match try_infer_transport_from_sysfs(sys_class_net, &iface) {
         Ok(connection_type) => connection_types.insert(connection_type),
         Err(error) => {
            warn!(message = %error.message, iface = %iface, "failed to classify supported sysfs interface");
            first_error.get_or_insert(error);
         }
      }
   }

   let connection_types = connection_types.into_vec();

   if connection_types.is_empty()
      && let Some(error) = first_error
   {
      return Err(Error::SupportedConnectionTypesDetectionFailed {
         message: error.message,
         code: error.code,
      });
   }

   Ok(connection_types)
}

fn is_virtual_sysfs_interface(interface_path: &Path) -> bool {
   // Virtual interfaces are exposed under sysfs `virtual/net`; physical
   // devices normally resolve through their backing device path. Excluding this
   // keeps bridges, tunnels, loopback-like devices, and veth pairs out of the
   // supported physical transport list.
   // https://docs.kernel.org/filesystems/sysfs.html
   path_has_exact_component(interface_path, "virtual")
      || path_has_exact_component(interface_path.join("device"), "virtual")
}

fn has_wifi_marker(interface_path: &Path) -> bool {
   interface_path.join("wireless").exists()
      || interface_path.join("phy80211").exists()
      || interface_path.join("ieee80211").exists()
      || interface_path.join("device").join("ieee80211").exists()
}

fn has_wwan_marker(interface_path: &Path) -> bool {
   interface_path.join("wwan").exists()
      || interface_path.join("device").join("wwan").exists()
      || path_has_exact_component(interface_path.join("device").join("subsystem"), "wwan")
}

fn path_has_exact_component(path: impl AsRef<Path>, marker: &str) -> bool {
   let Ok(path) = fs::canonicalize(path) else {
      return false;
   };

   path.components().any(|component| {
      component
         .as_os_str()
         .to_string_lossy()
         .eq_ignore_ascii_case(marker)
   })
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::fs::{self, File};
   use std::io::Write;
   use std::os::unix::fs as unix_fs;
   use std::path::PathBuf;
   use std::sync::atomic::{AtomicUsize, Ordering};

   static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

   #[test]
   fn limits_each_dbus_method_call_to_500_milliseconds() {
      assert_eq!(DBUS_METHOD_TIMEOUT, Duration::from_millis(500));
   }

   #[test]
   fn maps_connectivity_states() {
      assert_eq!(
         map_connectivity(NM_CONNECTIVITY_FULL),
         ConnectedState::Connected
      );
      assert_eq!(
         map_connectivity(NM_CONNECTIVITY_NONE),
         ConnectedState::Disconnected
      );
      assert_eq!(
         map_connectivity(NM_CONNECTIVITY_PORTAL),
         ConnectedState::Constrained
      );
      assert_eq!(
         map_connectivity(NM_CONNECTIVITY_LIMITED),
         ConnectedState::Constrained
      );
      assert_eq!(map_connectivity(0), ConnectedState::Unknown);
      assert_eq!(map_connectivity(99), ConnectedState::Unknown);
   }

   #[test]
   fn resolves_unknown_connectivity_from_global_state() {
      assert_eq!(
         connectivity_state_from_global_state(NM_STATE_CONNECTED_GLOBAL),
         ConnectedState::Connected
      );
      assert_eq!(
         connectivity_state_from_global_state(60),
         ConnectedState::Disconnected
      );
      assert_eq!(
         connectivity_state_from_global_state(20),
         ConnectedState::Disconnected
      );
   }

   #[test]
   fn maps_metered_states_without_collapsing_unknown() {
      assert_eq!(metered_status(NM_METERED_UNKNOWN), None);
      assert_eq!(metered_status(NM_METERED_YES), Some(true));
      assert_eq!(metered_status(NM_METERED_NO), Some(false));
      assert_eq!(metered_status(NM_METERED_GUESS_YES), Some(true));
      assert_eq!(metered_status(NM_METERED_GUESS_NO), Some(false));
      assert_eq!(metered_status(99), None);
   }

   #[test]
   fn maps_network_manager_device_types() {
      assert_eq!(
         map_device_type(NM_DEVICE_TYPE_ETHERNET),
         ConnectionType::Ethernet
      );
      assert_eq!(map_device_type(NM_DEVICE_TYPE_WIFI), ConnectionType::Wifi);
      assert_eq!(
         map_device_type(NM_DEVICE_TYPE_MODEM),
         ConnectionType::Cellular
      );
      assert_eq!(map_device_type(999), ConnectionType::Unknown);
   }

   #[test]
   fn treats_non_cellular_connection_types_as_not_roaming() {
      for connection_type in [
         ConnectionType::Wifi,
         ConnectionType::Ethernet,
         ConnectionType::Unknown,
      ] {
         assert_eq!(
            connection_type_roaming_status(connection_type, || {
               panic!("non-cellular transport must not query ModemManager")
            }),
            Some(false)
         );
      }

      assert_eq!(
         connection_type_roaming_status(ConnectionType::Cellular, || None),
         None
      );
   }

   #[test]
   fn collects_supported_connection_types_from_network_manager_device_types() {
      assert_eq!(
         collect_supported_connection_types([
            NM_DEVICE_TYPE_MODEM,
            999,
            NM_DEVICE_TYPE_WIFI,
            NM_DEVICE_TYPE_MODEM,
            NM_DEVICE_TYPE_ETHERNET,
         ]),
         vec![
            ConnectionType::Wifi,
            ConnectionType::Ethernet,
            ConnectionType::Cellular,
         ]
      );
   }

   #[test]
   fn skips_network_manager_devices_that_cannot_be_read() {
      let devices = [
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/1").unwrap(),
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/2").unwrap(),
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/3").unwrap(),
      ];

      assert_eq!(
         collect_supported_connection_types_from_devices(devices, |device| {
            match device.as_str() {
               "/org/freedesktop/NetworkManager/Devices/1" => Ok(NM_DEVICE_TYPE_ETHERNET),
               "/org/freedesktop/NetworkManager/Devices/2" => Err("device disappeared"),
               "/org/freedesktop/NetworkManager/Devices/3" => Ok(NM_DEVICE_TYPE_WIFI),
               _ => unreachable!(),
            }
         })
         .unwrap(),
         vec![ConnectionType::Wifi, ConnectionType::Ethernet]
      );
   }

   #[test]
   fn reports_failure_when_no_network_manager_device_can_be_read() {
      let devices = [
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/1").unwrap(),
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/2").unwrap(),
      ];

      assert!(
         collect_supported_connection_types_from_devices(devices, |_| {
            Err::<u32, _>("device disappeared")
         })
         .is_err()
      );
   }

   #[test]
   fn reports_failure_when_only_unknown_network_manager_devices_can_be_read() {
      let devices = [
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/1").unwrap(),
         OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/2").unwrap(),
      ];

      assert!(
         collect_supported_connection_types_from_devices(devices, |device| {
            match device.as_str() {
               "/org/freedesktop/NetworkManager/Devices/1" => Ok(999),
               "/org/freedesktop/NetworkManager/Devices/2" => Err("device disappeared"),
               _ => unreachable!(),
            }
         })
         .is_err()
      );
   }

   #[test]
   fn combines_constraint_signals_without_collapsing_unknown() {
      assert_eq!(
         constrained_status(ConnectedState::Connected, Some(false), Some(false)),
         Some(false)
      );
      assert_eq!(
         constrained_status(ConnectedState::Constrained, None, None),
         Some(true)
      );
      assert_eq!(
         constrained_status(ConnectedState::Connected, Some(true), None),
         Some(true)
      );
      assert_eq!(
         constrained_status(ConnectedState::Connected, None, Some(true)),
         Some(true)
      );
      assert_eq!(
         constrained_status(ConnectedState::Connected, Some(false), None),
         None
      );
      assert_eq!(
         constrained_status(ConnectedState::Connected, None, None),
         None
      );
      assert_eq!(
         constrained_status(
            connectivity_state_from_global_state(NM_STATE_CONNECTED_GLOBAL),
            Some(false),
            Some(false),
         ),
         Some(false)
      );
   }

   #[test]
   fn defaults_to_unknown_connection_details() {
      let details = ConnectionDetails::default();

      assert_eq!(details.metered, None);
      assert_eq!(details.roaming, None);
      assert_eq!(details.connection_type, ConnectionType::Unknown);
   }

   #[test]
   fn maps_roaming_registration_states_without_collapsing_unknown() {
      for registration_state in [
         MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING,
         MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_SMS_ONLY,
         MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING_CSFB_NOT_PREFERRED,
      ] {
         let roaming = roaming_status(registration_state);

         assert_eq!(roaming, Some(true));
         assert_eq!(
            constrained_status(ConnectedState::Connected, Some(false), roaming),
            Some(true)
         );
      }

      assert_eq!(roaming_status(1), Some(false));
      assert_eq!(
         roaming_status(MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN),
         None
      );
      assert_eq!(roaming_status(99), None);
   }

   #[test]
   fn combines_multiple_policy_signals_conservatively() {
      assert_eq!(
         combine_policy_states([Some(false), Some(false)]),
         Some(false)
      );
      assert_eq!(combine_policy_states([Some(false), None]), None);
      assert_eq!(combine_policy_states([None, Some(false)]), None);
      assert_eq!(combine_policy_states([None, None]), None);
      assert_eq!(combine_policy_states([Some(true), None]), Some(true));
      assert_eq!(combine_policy_states([None, Some(true)]), Some(true));
      assert_eq!(combine_policy_states([]), None);
   }

   #[test]
   fn validates_modem_manager_modem_paths() {
      assert!(is_modem_manager_modem_path(
         "/org/freedesktop/ModemManager1/Modem/0"
      ));
      assert!(!is_modem_manager_modem_path("/"));
      assert!(!is_modem_manager_modem_path(
         "/org/freedesktop/NetworkManager/Devices/0"
      ));
   }

   #[test]
   fn parses_default_ipv4_route_interface() {
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t015018AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
";

      assert_eq!(
         default_ipv4_route_interface(route_table),
         Some("eth0".into())
      );
   }

   #[test]
   fn passive_fallback_reports_unknown_policy_flags() {
      let temp = TempDir::new();
      let iface = temp.path().join("eth0");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "1\n");
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t015018AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
";

      let status = fallback_connection_status_from_routes(route_table, "", temp.path());

      assert!(status.connected);
      assert_eq!(status.metered, None);
      assert_eq!(status.constrained, None);
      assert_eq!(status.connection_type, ConnectionType::Ethernet);
   }

   #[test]
   fn ignores_loopback_default_route() {
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
lo\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0
";

      assert_eq!(default_ipv4_route_interface(route_table), None);
   }

   #[test]
   fn ignores_down_default_route() {
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t015018AC\t0002\t0\t0\t0\t00000000\t0\t0\t0
";

      assert_eq!(default_ipv4_route_interface(route_table), None);
   }

   #[test]
   fn returns_none_without_default_route() {
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t005018AC\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0
";

      assert_eq!(default_ipv4_route_interface(route_table), None);
   }

   #[test]
   fn ignores_malformed_route_rows() {
      let route_table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
malformed
eth0\t00000000\t015018AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
";

      assert_eq!(
         default_ipv4_route_interface(route_table),
         Some("eth0".into())
      );
   }

   #[test]
   fn parses_ipv6_default_route_interface() {
      let route_table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0
";

      assert_eq!(
         default_ipv6_route_interface(route_table),
         Some("eth0".into())
      );
   }

   #[test]
   fn ignores_ipv6_loopback_default_route() {
      let route_table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
";

      assert_eq!(default_ipv6_route_interface(route_table), None);
   }

   #[test]
   fn ignores_down_ipv6_default_route() {
      let route_table = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000002 eth0
";

      assert_eq!(default_ipv6_route_interface(route_table), None);
   }

   #[test]
   fn returns_none_without_ipv6_default_route() {
      let route_table = "\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
";

      assert_eq!(default_ipv6_route_interface(route_table), None);
   }

   #[test]
   fn ignores_malformed_ipv6_route_rows() {
      let route_table = "\
malformed
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0
";

      assert_eq!(
         default_ipv6_route_interface(route_table),
         Some("eth0".into())
      );
   }

   #[test]
   fn infers_wifi_from_wireless_directory() {
      let temp = TempDir::new();
      let iface = temp.path().join("wlp0s20f3");
      fs::create_dir_all(iface.join("wireless")).unwrap();

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "wlp0s20f3"),
         ConnectionType::Wifi
      );
   }

   #[test]
   fn infers_wifi_from_ieee80211_marker() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(iface.join("ieee80211")).unwrap();

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "net0"),
         ConnectionType::Wifi
      );
   }

   #[test]
   fn infers_wifi_from_phy80211_marker() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(iface.join("phy80211")).unwrap();

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "net0"),
         ConnectionType::Wifi
      );
   }

   #[test]
   fn does_not_infer_wifi_from_80211_path_fragment() {
      let temp = TempDir::new();
      let sys_class_net = temp.path().join("not80211-device");
      let iface = sys_class_net.join("net0");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "1\n");

      assert_eq!(
         infer_transport_from_sysfs(&sys_class_net, "net0"),
         ConnectionType::Ethernet
      );
   }

   #[test]
   fn infers_cellular_from_wwan_marker() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(iface.join("device").join("wwan")).unwrap();

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "net0"),
         ConnectionType::Cellular
      );
   }

   #[test]
   fn does_not_infer_cellular_from_wwan_path_fragment() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      let subsystem_target = temp.path().join("notwwan-bus");
      fs::create_dir_all(iface.join("device")).unwrap();
      fs::create_dir_all(&subsystem_target).unwrap();
      unix_fs::symlink(&subsystem_target, iface.join("device").join("subsystem")).unwrap();
      write_file(iface.join("type"), "1\n");

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "net0"),
         ConnectionType::Ethernet
      );
   }

   #[test]
   fn infers_ethernet_from_arphrd_ether_type() {
      let temp = TempDir::new();
      let iface = temp.path().join("enp0s1");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "1\n");

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "enp0s1"),
         ConnectionType::Ethernet
      );
   }

   #[test]
   fn supported_types_from_sysfs_ignores_virtual_interfaces() {
      let temp = TempDir::new();
      let physical = temp.path().join("enp0s1");
      let virtual_iface = temp.path().join("virtual").join("net").join("veth0");
      fs::create_dir_all(physical.join("wireless")).unwrap();
      fs::create_dir_all(&virtual_iface).unwrap();
      write_file(virtual_iface.join("type"), "1\n");
      unix_fs::symlink(&virtual_iface, temp.path().join("veth0")).unwrap();

      assert_eq!(
         supported_types_from_sysfs(temp.path()).unwrap(),
         vec![ConnectionType::Wifi]
      );
   }

   #[test]
   fn supported_types_from_sysfs_returns_empty_without_transport_signal() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "772\n");

      assert_eq!(
         supported_types_from_sysfs(temp.path()).unwrap(),
         Vec::<ConnectionType>::new()
      );
   }

   #[test]
   fn supported_types_from_sysfs_reports_interface_type_failure() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "not-an-interface-type\n");

      assert!(matches!(
         supported_types_from_sysfs(temp.path()),
         Err(Error::SupportedConnectionTypesDetectionFailed { .. })
      ));
   }

   #[test]
   fn supported_types_from_sysfs_reports_missing_interface_type() {
      let temp = TempDir::new();
      fs::create_dir_all(temp.path().join("net0")).unwrap();

      assert!(matches!(
         supported_types_from_sysfs(temp.path()),
         Err(Error::SupportedConnectionTypesDetectionFailed { .. })
      ));
   }

   #[test]
   fn supported_types_from_sysfs_returns_partial_results_despite_failure() {
      let temp = TempDir::new();
      let wifi = temp.path().join("wlp0s20f3");
      let unreadable = temp.path().join("net0");
      fs::create_dir_all(wifi.join("wireless")).unwrap();
      fs::create_dir_all(unreadable).unwrap();

      assert_eq!(
         supported_types_from_sysfs(temp.path()).unwrap(),
         vec![ConnectionType::Wifi]
      );
   }

   #[test]
   fn supported_types_from_sysfs_reports_enumeration_failure() {
      let temp = TempDir::new();
      let missing_path = temp.path().join("missing");

      assert!(supported_types_from_sysfs(&missing_path).is_err());
   }

   #[test]
   fn returns_unknown_when_sysfs_has_no_transport_signal() {
      let temp = TempDir::new();
      let iface = temp.path().join("net0");
      fs::create_dir_all(&iface).unwrap();
      write_file(iface.join("type"), "772\n");

      assert_eq!(
         infer_transport_from_sysfs(temp.path(), "net0"),
         ConnectionType::Unknown
      );
   }

   fn write_file(path: impl AsRef<Path>, contents: &str) {
      let mut file = File::create(path).unwrap();
      file.write_all(contents.as_bytes()).unwrap();
   }

   struct TempDir {
      path: PathBuf,
   }

   impl TempDir {
      fn new() -> Self {
         let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
         let path = std::env::temp_dir().join(format!(
            "tauri-plugin-connectivity-linux-test-{}-{id}",
            std::process::id()
         ));

         if path.exists() {
            fs::remove_dir_all(&path).unwrap();
         }
         fs::create_dir_all(&path).unwrap();

         Self { path }
      }

      fn path(&self) -> &Path {
         &self.path
      }
   }

   impl Drop for TempDir {
      fn drop(&mut self) {
         let _ = fs::remove_dir_all(&self.path);
      }
   }
}
