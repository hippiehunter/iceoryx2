// Copyright (c) 2023 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache Software License 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0, or the MIT license
// which is available at https://opensource.org/licenses/MIT.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Examples
//!
//! ```
//! use iceoryx2::prelude::*;
//! use iceoryx2::config::Config;
//! use iceoryx2_bb_system_types::path::*;
//!
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//!
//! // create a default config and override some entries
//! let mut custom_config = Config::default();
//! custom_config.defaults.publish_subscribe.max_publishers = 5;
//! custom_config.global.service.directory = Path::new(b"another_service_dir")?;
//!
//! let node = NodeBuilder::new()
//!     .config(&custom_config)
//!     .create::<ipc::Service>()?;
//!
//! let service = node.service_builder(&"MyServiceName".try_into()?)
//!     .publish_subscribe::<u64>()
//!     .open_or_create()?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Set Global Config From Custom File
//!
//! The [`crate::config::Config::setup_global_config_from_file()`] call must be the first
//! call in the system. If another
//! instance accesses the global config, it will be loaded with default values and can no longer
//! be overridden with new values from a custom file.
//!
//! ```no_run
//! use iceoryx2::config::Config;
//! use iceoryx2_bb_system_types::file_path::FilePath;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//!
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! Config::setup_global_config_from_file(
//!     &FilePath::new(b"my/custom/config/file.toml")?)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Generate Config From Custom File
//!
//! ```no_run
//! use iceoryx2::config::Config;
//! use iceoryx2_bb_system_types::file_path::FilePath;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//!
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let custom_config = Config::from_file(
//!     &FilePath::new(b"my/custom/config/file.toml")?)?;
//! # Ok(())
//! # }
//! ```

use core::time::Duration;

use alloc::string::String;

use iceoryx2_bb_container::semantic_string::SemanticString;
use iceoryx2_bb_elementary::{
    CallbackProgression, allocation_strategy::AllocationStrategy, lazy_singleton::*,
};
use iceoryx2_bb_posix::{
    file::{FileBuilder, FileOpenError},
    shared_memory::AccessMode,
    system_configuration::GLOBAL_CONFIG_PATH,
};
use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_bb_system_types::file_path::FilePath;
use iceoryx2_bb_system_types::path::Path;
use iceoryx2_cal::security::mode::SecurityMode;
use serde::{Deserialize, Serialize};

use iceoryx2_log::{debug, fail, fatal_panic, info, trace, warn};

use crate::port::backpressure_strategy::BackpressureStrategy;

use iceoryx2_pal_configuration::ICEORYX2_ROOT_PATH;

const DEFAULT_CONFIG_FILE_NAME: &[u8] = b"iceoryx2.toml";
const RELATIVE_LOCAL_CONFIG_PATH: &[u8] = b"config";
const RELATIVE_CONFIG_FILE_PATH: &[u8] = b"iceoryx2";
// tick time that is used for IO operations
pub(crate) const IO_TICK_TIME: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum ConfigIterationFailure {
    UnableToAcquireCurrentUserDetails,
    TooLongUserConfigDirectory,
    ConfigDirectoryNotAvailable,
}

/// Failures occurring while creating a new [`Config`] object with [`Config::from_file()`] or
/// [`Config::setup_global_config_from_file()`]
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ConfigCreationError {
    /// The config file could not be read.
    FailedToReadConfigFileContents,
    /// Parts of the config file could not be deserialized. Indicates some kind of syntax error.
    UnableToDeserializeContents,
    /// Insufficient permissions to open the config file.
    InsufficientPermissions,
    /// The provided config file does not exist
    ConfigFileDoesNotExist,
    /// Since the config file could not be opened
    UnableToOpenConfigFile,
}

impl core::fmt::Display for ConfigCreationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConfigCreationError::{self:?}")
    }
}

impl core::error::Error for ConfigCreationError {}

/// All configurable settings of a [`Service`](crate::service::Service).
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Service {
    /// A list of directories where iceoryx2 will look for `.fbs` flatbuffer schemas. If no path is
    /// provided, iceoryx2 will perform no lookup and the user must explicitly define the path to
    /// the flatbuffer schemas.
    pub flatbuffer_schema_path: Option<Path>,
    /// The directory in which all service files are stored
    pub directory: Path,
    /// The suffix of the ports data segment
    pub data_segment_suffix: FileName,
    /// The suffix of the static config file
    pub static_config_storage_suffix: FileName,
    /// The suffix of the dynamic config file
    pub dynamic_config_storage_suffix: FileName,
    /// The suffix of a one-to-one connection
    pub connection_suffix: FileName,
    /// The suffix of a one-to-one connection
    pub event_connection_suffix: FileName,
    /// The suffix of the blackboard management data segment
    pub blackboard_mgmt_suffix: FileName,
    /// The suffix of the blackboard payload data segment
    pub blackboard_data_suffix: FileName,
    /// The suffix of the type definition file
    pub type_definition_suffix: FileName,
    /// Whenever an existing [`Service`](crate::service::Service) is opened the builder will
    /// scan for dead nodes and clean up the stale resources that might block another process.
    pub cleanup_dead_nodes_on_open: bool,
}

impl Default for Service {
    fn default() -> Self {
        Self {
            flatbuffer_schema_path: None,
            directory: unsafe { Path::new_unchecked_const(b"services") },
            data_segment_suffix: unsafe { FileName::new_unchecked_const(b".data") },
            static_config_storage_suffix: unsafe { FileName::new_unchecked_const(b".service") },
            dynamic_config_storage_suffix: unsafe { FileName::new_unchecked_const(b".dynamic") },
            connection_suffix: unsafe { FileName::new_unchecked_const(b".connection") },
            event_connection_suffix: unsafe { FileName::new_unchecked_const(b".event") },
            blackboard_mgmt_suffix: unsafe { FileName::new_unchecked_const(b".blackboard_mgmt") },
            blackboard_data_suffix: unsafe { FileName::new_unchecked_const(b".blackboard_data") },
            type_definition_suffix: unsafe { FileName::new_unchecked_const(b".type_definition") },
            cleanup_dead_nodes_on_open: true,
        }
    }
}

/// A POSIX file mode (permission bits plus set-group-id / sticky bits) used by the multi-user
/// settings of secured mode.
///
/// In TOML it is written as an octal string, e.g. `"1777"`, `"2770"` or `"0660"` (an optional
/// `0o` prefix is accepted). A TOML octal integer literal (`0o2770`) works as well; a plain
/// decimal integer is taken literally and therefore almost always wrong.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct FileMode(u32);

impl FileMode {
    /// Creates a mode from its raw bits, e.g. `FileMode::new(0o2770)`. Bits outside of `0o7777`
    /// are rejected.
    pub const fn new(bits: u32) -> Option<Self> {
        if bits > 0o7777 {
            None
        } else {
            Some(Self(bits))
        }
    }

    /// The raw mode bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Parses an octal mode string such as `"2770"` or `"0o1777"`.
    pub fn from_octal_str(value: &str) -> Option<Self> {
        let digits = value.trim();
        let digits = digits.strip_prefix("0o").unwrap_or(digits);
        if digits.is_empty() || digits.len() > 4 {
            return None;
        }
        u32::from_str_radix(digits, 8).ok().and_then(Self::new)
    }

    /// The mode as [`Permission`](iceoryx2_bb_posix::permission::Permission).
    pub fn as_permission(&self) -> iceoryx2_bb_posix::permission::Permission {
        iceoryx2_bb_posix::permission::Permission::from_bits(self.0)
    }
}

impl core::fmt::Display for FileMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

impl Serialize for FileMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&alloc::format!("{:04o}", self.0))
    }
}

impl<'de> Deserialize<'de> for FileMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ModeVisitor;
        impl serde::de::Visitor<'_> for ModeVisitor {
            type Value = FileMode;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("an octal file mode string like \"2770\"")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<FileMode, E> {
                FileMode::from_octal_str(v)
                    .ok_or_else(|| E::custom(alloc::format!("invalid octal file mode \"{v}\"")))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<FileMode, E> {
                u32::try_from(v)
                    .ok()
                    .and_then(FileMode::new)
                    .ok_or_else(|| E::custom(alloc::format!("invalid file mode {v}")))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<FileMode, E> {
                u32::try_from(v)
                    .ok()
                    .and_then(FileMode::new)
                    .ok_or_else(|| E::custom(alloc::format!("invalid file mode {v}")))
            }
        }
        deserializer.deserialize_any(ModeVisitor)
    }
}

/// Resolves a group given by name (`"sipwriters"`) or numerically (`"3000"`) to its gid.
pub(crate) fn resolve_group(group: &FileName) -> Option<u32> {
    let name = core::str::from_utf8(group.as_bytes()).ok()?;
    if let Ok(gid) = name.parse::<u32>() {
        return Some(gid);
    }
    let group_name = iceoryx2_bb_system_types::group_name::GroupName::new(name.as_bytes()).ok()?;
    iceoryx2_bb_posix::group::Group::from_name(&group_name)
        .ok()
        .map(|g| g.gid().value())
}

/// IAM (Identity and Access Management) configuration for secured services.
///
/// This configuration is only used when [`NodeSecurity::mode`] is set to
/// [`SecurityMode::Secured`].
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct IamConfig {
    /// Base path for IAM control channel endpoints.
    ///
    /// On Linux, IAM endpoints will be created as Unix domain sockets under this path.
    /// On Windows, named pipes will be created with names derived from this path.
    pub endpoint_base: Path,
    /// Connection timeout for IAM client handshake.
    ///
    /// This is the maximum time a client will wait when connecting to an IAM server.
    pub connect_timeout: Duration,
    /// Directory containing TOML policy files for per-service authorization.
    ///
    /// Policy files are named `{sanitized_service_name}.toml` and loaded
    /// automatically when a secured service is created. If no policy file
    /// exists for a service, the [`DefaultPolicy`](crate::iam::DefaultPolicy)
    /// is used.
    pub policy_dir: Path,
    /// Path to the audit log file for recording IAM authorization decisions.
    ///
    /// The file is opened in append mode and written in JSON Lines format.
    /// Set to an empty path to disable audit logging.
    pub audit_log_path: Path,
    /// File mode of the IAM control socket (e.g. `"0660"` or `"0666"`). When unset the socket is
    /// accessible by its owner only (single-user default). Connecting needs write access, so the
    /// group/others bits decide who may *talk* to the IAM server; what they may *do* is decided
    /// by the policy, never by this mode.
    pub endpoint_mode: Option<FileMode>,
    /// Group (name or numeric gid) the IAM control socket is handed to when
    /// [`IamConfig::endpoint_mode`] grants group access. Optional; without it the socket keeps
    /// the group it inherits from its directory.
    pub endpoint_group: Option<FileName>,
}

impl Default for IamConfig {
    fn default() -> Self {
        Self {
            endpoint_base: Path::new(b"iam").unwrap(),
            connect_timeout: Duration::from_secs(5),
            policy_dir: Path::new(b"iam/policies").unwrap(),
            audit_log_path: Path::new(b"iam/audit.log").unwrap(),
            endpoint_mode: None,
            endpoint_group: None,
        }
    }
}

/// Security configuration for a [`Node`](crate::node::Node).
///
/// Controls whether services created by this node operate in public mode (default)
/// or secured mode with IAM authentication.
///
/// # Example TOML Configuration
///
/// ```toml
/// [global.node.security]
/// mode = "secured"
///
/// [global.node.security.iam]
/// endpoint-base = "iam"
///
/// [global.node.security.iam.connect-timeout]
/// secs = 5
/// nanos = 0
/// ```
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct NodeSecurity {
    /// Security mode for all services created by this node.
    ///
    /// - [`SecurityMode::Public`]: Default mode, no authentication required.
    /// - [`SecurityMode::Secured`]: IAM authentication required for all service operations.
    pub mode: SecurityMode,
    /// IAM configuration (only used when mode is [`SecurityMode::Secured`]).
    pub iam: IamConfig,
    /// Enables multi-user secured mode (only used when mode is [`SecurityMode::Secured`]).
    ///
    /// The mode (e.g. `"1777"` sticky world-writable, or `"2770"` group-shared set-group-id)
    /// that the shared directories - the root path, the node directory and the service
    /// directory - are created with when they do not yet exist. When set, the metadata that other
    /// users need to open a service and to observe nodes (static service config, node details,
    /// node monitor files, service dynamic config, event channels) is shared with the group
    /// and/or others as far as the group/others bits of this mode allow. Data segments and
    /// connection channels stay anonymous and are only handed out by the IAM server.
    ///
    /// When unset (default) every resource is accessible by its creating user only.
    pub shared_directory_mode: Option<FileMode>,
    /// The group (name or numeric gid) shared directories and shared POSIX shared memory are
    /// handed to when [`NodeSecurity::shared_directory_mode`] grants group access. The creating
    /// process must be `root` or a member of the group.
    pub shared_group: Option<FileName>,
}

impl Default for NodeSecurity {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Public,
            iam: IamConfig::default(),
            shared_directory_mode: None,
            shared_group: None,
        }
    }
}

impl NodeSecurity {
    /// Returns `true` when multi-user secured mode is enabled, i.e. the node is secured and a
    /// [`NodeSecurity::shared_directory_mode`] is configured.
    pub fn is_multi_user(&self) -> bool {
        self.mode.is_secured() && self.shared_directory_mode.is_some()
    }

    /// The access with which metadata resources are shared with other users.
    pub(crate) fn metadata_access(&self) -> iceoryx2_cal::named_concept::SharedAccess {
        match (self.mode.is_secured(), self.shared_directory_mode) {
            (true, Some(mode)) => iceoryx2_cal::named_concept::SharedAccess::from_mode(
                mode.as_permission(),
                self.shared_group.as_ref().and_then(resolve_group),
            ),
            _ => iceoryx2_cal::named_concept::SharedAccess::owner_only(),
        }
    }

    /// The access with which the IAM control socket is shared with other users.
    pub(crate) fn endpoint_access(&self) -> iceoryx2_cal::named_concept::SharedAccess {
        match (self.mode.is_secured(), self.iam.endpoint_mode) {
            (true, Some(mode)) => iceoryx2_cal::named_concept::SharedAccess::from_mode(
                mode.as_permission(),
                self.iam.endpoint_group.as_ref().and_then(resolve_group),
            ),
            _ => iceoryx2_cal::named_concept::SharedAccess::owner_only(),
        }
    }
}

/// All configurable settings of a [`Node`](crate::node::Node).
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Node {
    /// The directory in which all node files are stored
    pub directory: Path,
    /// The suffix of the monitor token
    pub monitor_suffix: FileName,
    /// The suffix of the files where the node configuration is stored.
    pub static_config_suffix: FileName,
    /// The suffix of the service tags.
    pub service_tag_suffix: FileName,
    /// The suffix of the port tags.
    pub port_tag_suffix: FileName,
    /// The suffix of the global management segment.
    pub global_mgmt_suffix: FileName,
    /// When true, the [`NodeBuilder`](crate::node::NodeBuilder) checks for dead nodes and
    /// cleans up all their stale resources whenever a new [`Node`](crate::node::Node) is
    /// created.
    pub cleanup_dead_nodes_on_creation: bool,
    /// When true, the [`NodeBuilder`](crate::node::NodeBuilder) checks for dead nodes and
    /// cleans up all their stale resources whenever an existing [`Node`](crate::node::Node) is
    /// going out of scope.
    pub cleanup_dead_nodes_on_destruction: bool,
    /// Security configuration for services created by this node.
    pub security: NodeSecurity,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            directory: unsafe { Path::new_unchecked_const(b"nodes") },
            monitor_suffix: unsafe { FileName::new_unchecked_const(b".node_monitor") },
            global_mgmt_suffix: unsafe { FileName::new_unchecked_const(b".global_mgmt") },
            static_config_suffix: unsafe { FileName::new_unchecked_const(b".details") },
            service_tag_suffix: unsafe { FileName::new_unchecked_const(b".service_tag") },
            port_tag_suffix: unsafe { FileName::new_unchecked_const(b".port_tag") },
            cleanup_dead_nodes_on_creation: true,
            cleanup_dead_nodes_on_destruction: true,
            security: NodeSecurity::default(),
        }
    }
}

/// The global settings
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Global {
    root_path: Path,
    /// Prefix used for all files created during runtime
    pub prefix: FileName,
    /// [`Service`](crate::service::Service) settings
    pub service: Service,
    /// [`Node`](crate::node::Node) settings
    pub node: Node,
    /// Defines the time how long the process will wait until an entity, that shares inter-process
    /// resources with others, is opened or created. This entity could be for instance a service
    pub creation_timeout: Duration,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            root_path: unsafe { Path::new_unchecked_const(ICEORYX2_ROOT_PATH) },
            #[cfg(feature = "std")]
            prefix: unsafe { FileName::new_unchecked_const(b"iox2_") },
            #[cfg(not(feature = "std"))]
            prefix: unsafe { FileName::new_unchecked_const(b"iox2_no_std_") },
            service: Service::default(),
            node: Node::default(),
            creation_timeout: Duration::from_secs(1),
        }
    }
}
impl Global {
    /// The absolute path to the service directory where all static service infos are stored
    pub fn service_dir(&self) -> Path {
        let mut path = *self.root_path();
        path.add_path_entry(&self.service.directory)
            .expect("Service directory is always valid.");
        path
    }

    /// The absolute path to the node directory where all node details are stored
    pub fn node_dir(&self) -> Path {
        let mut path = *self.root_path();
        path.add_path_entry(&self.node.directory)
            .expect("Node directory is always valid.");
        path
    }

    /// The path under which all other directories or files will be created
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Defines the path under which all other directories or files will be created
    pub fn set_root_path(&mut self, value: &Path) {
        self.root_path = *value;
    }
}

/// Default settings. These values are used when the user in the code does not specify anything
/// else.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Defaults {
    /// Default settings for the messaging pattern publish-subscribe
    pub publish_subscribe: PublishSubscribe,
    /// Default settings for the messaging pattern event
    pub event: Event,
    /// Default settings for the messaging pattern request-response
    pub request_response: RequestResonse,
    /// Default settings for the messaging pattern blackboard
    pub blackboard: Blackboard,
}

/// Default settings for the publish-subscribe messaging pattern. These settings are used unless
/// the user specifies custom QoS or port settings.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct PublishSubscribe {
    /// The maximum amount of supported [`Subscriber`](crate::port::subscriber::Subscriber)
    pub max_subscribers: usize,
    /// The maximum amount of supported [`Publisher`](crate::port::publisher::Publisher)
    pub max_publishers: usize,
    /// The maximum amount of supported [`Node`](crate::node::Node)s. Defines indirectly how many
    /// processes can open the service at the same time.
    pub max_nodes: usize,
    /// The maximum buffer size a [`Subscriber`](crate::port::subscriber::Subscriber) can have
    pub subscriber_max_buffer_size: usize,
    /// The maximum amount of [`Sample`](crate::sample::Sample)s a [`Subscriber`](crate::port::subscriber::Subscriber) can
    /// hold at the same time.
    pub subscriber_max_borrowed_samples: usize,
    /// The maximum amount of [`SampleMut`](crate::sample_mut::SampleMut)s a [`Publisher`](crate::port::publisher::Publisher) can
    /// loan at the same time.
    pub publisher_max_loaned_samples: usize,
    /// The maximum history size a [`Subscriber`](crate::port::subscriber::Subscriber) can request from a
    /// [`crate::port::publisher::Publisher`].
    pub publisher_history_size: usize,
    /// Defines how the [`Subscriber`](crate::port::subscriber::Subscriber) buffer behaves when it is
    /// full. When safe overflow is activated, the [`Publisher`](crate::port::publisher::Publisher) will
    /// replace the oldest [`Sample`](crate::sample::Sample) with the newest one.
    pub enable_safe_overflow: bool,
    /// If safe overflow is deactivated it defines the deliver strategy of the
    /// [`Publisher`](crate::port::publisher::Publisher) when the [`Subscriber`](crate::port::subscriber::Subscriber)s
    /// buffer is full.
    pub backpressure_strategy: BackpressureStrategy,
    /// Defines the size of the internal [`Subscriber`](crate::port::subscriber::Subscriber)
    /// buffer that contains expired connections. An
    /// connection is expired when the [`Publisher`](crate::port::publisher::Publisher)
    /// disconnected from a service and the connection
    /// still contains unconsumed [`Sample`](crate::sample::Sample)s.
    pub subscriber_expired_connection_buffer: usize,
    /// Defines the default [`AllocationStrategy`] used by the
    /// [`Publisher`](crate::port::publisher::Publisher) when the initially preallocated memory is
    /// insufficient.
    pub publisher_allocation_strategy: AllocationStrategy,
}

impl Default for PublishSubscribe {
    fn default() -> Self {
        Self {
            max_subscribers: 8,
            max_publishers: 2,
            max_nodes: 20,
            publisher_history_size: 0,
            subscriber_max_buffer_size: 2,
            subscriber_max_borrowed_samples: 2,
            publisher_max_loaned_samples: 2,
            enable_safe_overflow: true,
            backpressure_strategy: BackpressureStrategy::RetryUntilDelivered,
            subscriber_expired_connection_buffer: 128,
            publisher_allocation_strategy: AllocationStrategy::Static,
        }
    }
}

/// Default settings for the event messaging pattern. These settings are used unless
/// the user specifies custom QoS or port settings.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Event {
    /// The maximum amount of supported [`Listener`](crate::port::listener::Listener)
    pub max_listeners: usize,
    /// The maximum amount of supported [`Notifier`](crate::port::notifier::Notifier)
    pub max_notifiers: usize,
    /// The maximum amount of supported [`Node`](crate::node::Node)s. Defines indirectly how many
    /// processes can open the service at the same time.
    pub max_nodes: usize,
    /// The largest event id supported by the event service
    pub event_id_max_value: usize,
    /// Defines the maximum allowed time between two consecutive notifications. If a notification
    /// is not sent after the defined time, every [`Listener`](crate::port::listener::Listener)
    /// that is attached to a [`WaitSet`](crate::waitset::WaitSet) will be notified.
    pub deadline: Option<Duration>,
    /// Defines the event id value that is emitted after a new notifier was created.
    pub notifier_created_event: Option<usize>,
    /// Defines the event id value that is emitted before a new notifier is dropped.
    pub notifier_dropped_event: Option<usize>,
    /// Defines the event id value that is emitted if a notifier was identified as dead.
    pub notifier_dead_event: Option<usize>,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            max_listeners: 16,
            max_notifiers: 16,
            max_nodes: 36,
            event_id_max_value: 255,
            deadline: None,
            notifier_created_event: None,
            notifier_dropped_event: None,
            notifier_dead_event: None,
        }
    }
}

/// Default settings for the request response messaging pattern. These settings are used unless
/// the user specifies custom QoS or port settings.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct RequestResonse {
    /// Defines if the request buffer of the [`Service`](crate::service::Service) safely overflows.
    pub enable_safe_overflow_for_requests: bool,
    /// Defines if the response buffer of the [`Service`](crate::service::Service) safely overflows.
    pub enable_safe_overflow_for_responses: bool,
    /// The maximum of [`ActiveRequest`](crate::active_request::ActiveRequest)s a
    /// [`Server`](crate::port::server::Server) can hold in parallel per [`Client`](crate::port::client::Client).
    pub max_active_requests_per_client: usize,
    /// The maximum buffer size for [`Response`](crate::response::Response)s for a [`PendingResponse`](crate::pending_response::PendingResponse)
    /// for each [`Server`](crate::port::server::Server) connection.
    /// In a multi [`Server`](crate::port::server::Server) scenario every
    /// [`Response`](crate::response::Response) stream from every
    /// [`Server`](crate::port::server::Server) has the same buffer size resulting in a total
    /// buffer size of `NUMBER_OF_SERVERS * max_response_buffer_size`
    pub max_response_buffer_size: usize,
    /// The maximum amount of supported [`Server`](crate::port::server::Server)
    pub max_servers: usize,
    /// The maximum amount of supported [`Client`](crate::port::client::Client)
    pub max_clients: usize,
    /// The maximum amount of supported [`Node`](crate::node::Node)s. Defines indirectly how many
    /// processes can open the service at the same time.
    pub max_nodes: usize,
    /// The maximum amount of borrowed [`Response`](crate::response::Response) per
    /// [`PendingResponse`](crate::pending_response::PendingResponse) on the [`Client`](crate::port::client::Client) side.
    pub max_borrowed_responses_per_pending_response: usize,
    /// Defines how many [`RequestMut`](crate::request_mut::RequestMut) a [`Client`](crate::port::client::Client) can loan in parallel.
    pub max_loaned_requests: usize,
    /// Defines how many [`ResponseMut`](crate::response_mut::ResponseMut) a [`Server`](crate::port::server::Server)
    /// can loan in parallel per [`ActiveRequest`](crate::active_request::ActiveRequest).
    pub server_max_loaned_responses_per_request: usize,
    /// Defines the [`BackpressureStrategy`] when a [`Client`](crate::port::client::Client)
    /// could not deliver the request to the [`Server`](crate::port::server::Server).
    pub client_backpressure_strategy: BackpressureStrategy,
    /// Defines the [`BackpressureStrategy`] when a [`Server`](crate::port::server::Server)
    /// could not deliver the response to the [`Client`](crate::port::client::Client).
    pub server_backpressure_strategy: BackpressureStrategy,
    /// Defines the size of the internal [`Client`](crate::port::client::Client)
    /// buffer that contains expired connections. A
    /// connection is expired when the [`Server`](crate::port::server::Server)
    /// disconnected from a service and the connection
    /// still contains unconsumed [`Response`](crate::response::Response)s.
    pub client_expired_connection_buffer: usize,
    /// Allows the [`Server`](crate::port::server::Server) to receive
    /// [`RequestMut`](crate::response_mut::ResponseMut)s of
    /// [`Client`](crate::port::client::Client)s that are not interested in a
    /// [`Response`](crate::response::Response), meaning that the
    /// [`Server`](crate::port::server::Server) will receive the
    /// [`RequestMut`](crate::response_mut::ResponseMut) despite the corresponding
    /// [`PendingResponse`](crate::pending_response::PendingResponse) already went out-of-scope.
    /// So any [`Response`](crate::response::Response) sent by the
    /// [`Server`](crate::port::server::Server) would not be received by the corresponding
    /// [`Client`](crate::port::client::Client)s
    /// [`PendingResponse`](crate::pending_response::PendingResponse).
    ///
    /// Consider enabling this feature if you do not want to loose any
    /// [`RequestMut`](crate::response_mut::ResponseMut).
    pub enable_fire_and_forget_requests: bool,
    /// Defines the size of the internal [`Server`](crate::port::server::Server)
    /// buffer that contains expired connections. A
    /// connection is expired when the [`Client`](crate::port::client::Client)
    /// disconnected from a service and the connection
    /// still contains unconsumed [`ActiveRequest`](crate::active_request::ActiveRequest)s.
    pub server_expired_connection_buffer: usize,
    /// Defines the default [`AllocationStrategy`] used by the
    /// [`Client`](crate::port::client::Client) when the initially preallocated memory is
    /// insufficient.
    pub client_allocation_strategy: AllocationStrategy,
    /// Defines the default [`AllocationStrategy`] used by the
    /// [`Server`](crate::port::server::Server) when the initially preallocated memory is
    /// insufficient.
    pub server_allocation_strategy: AllocationStrategy,
}

impl Default for RequestResonse {
    fn default() -> Self {
        Self {
            enable_safe_overflow_for_requests: true,
            enable_safe_overflow_for_responses: true,
            max_active_requests_per_client: 4,
            max_response_buffer_size: 2,
            max_servers: 2,
            max_clients: 8,
            max_nodes: 20,
            max_borrowed_responses_per_pending_response: 2,
            max_loaned_requests: 2,
            server_max_loaned_responses_per_request: 2,
            client_backpressure_strategy: BackpressureStrategy::RetryUntilDelivered,
            server_backpressure_strategy: BackpressureStrategy::RetryUntilDelivered,
            client_expired_connection_buffer: 128,
            server_expired_connection_buffer: 128,
            enable_fire_and_forget_requests: true,
            client_allocation_strategy: AllocationStrategy::Static,
            server_allocation_strategy: AllocationStrategy::Static,
        }
    }
}

/// Default settings for the blackboard messaging pattern. These settings are used unless
/// the user specifies custom QoS or port settings.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Blackboard {
    /// The maximum amount of supported [`Reader`](crate::port::reader::Reader)s.
    pub max_readers: usize,
    /// The maximum amount of supported [`Node`](crate::node::Node)s. Defines indirectly how many
    /// processes can open the service at the same time.
    pub max_nodes: usize,
}

impl Default for Blackboard {
    fn default() -> Self {
        Self {
            max_readers: 8,
            max_nodes: 20,
        }
    }
}

/// Represents the configuration that iceoryx2 will utilize. It is divided into two sections:
/// the [`Global`] settings, which must align with the iceoryx2 instance the application intends to
/// join, and the [`Defaults`] for communication within that iceoryx2 instance. The user has the
/// flexibility to override both sections.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Default, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct Config {
    /// Global settings for the iceoryx2 instance
    pub global: Global,
    /// Default settings
    pub defaults: Defaults,
}

static ICEORYX2_CONFIG: LazySingleton<Config> = LazySingleton::<Config>::new();

impl Config {
    fn relative_local_config_path() -> Path {
        fatal_panic!(from "Config::relative_local_config_path",
            when Path::new(RELATIVE_LOCAL_CONFIG_PATH),
            "This should never happen! The relative local config path contains invalid symbols.")
    }

    /// The name of the default iceoryx2 config file
    pub fn default_config_file_name() -> FileName {
        fatal_panic!(from "Config::default_config_file",
            when FileName::new(DEFAULT_CONFIG_FILE_NAME),
            "This should never happen! The default config file name contains invalid symbols.")
    }

    /// Path to the default config file
    pub fn default_config_file_path() -> FilePath {
        fatal_panic!(from "Config::default_config_file_path",
            when FilePath::from_path_and_file(&Self::relative_local_config_path(), &Self::default_config_file_name()),
            "This should never happen! The default config file path contains invalid symbols.")
    }

    /// Relative path to the config file
    pub fn relative_config_path() -> Path {
        fatal_panic!(from "Config::relative_config_path",
            when Path::new(RELATIVE_CONFIG_FILE_PATH),
            "This should never happen! The relative config path contains invalid symbols.")
    }

    /// Path to the default user config file
    pub fn default_user_config_file_path() -> FilePath {
        fatal_panic!(from "Config::default_config_file_path",
            when FilePath::from_path_and_file(&Self::relative_config_path(), &Self::default_config_file_name()),
            "This should never happen! The default config file path contains invalid symbols.")
    }

    fn load_user_config_path(origin: &str, msg: &str) -> Result<FilePath, ConfigIterationFailure> {
        let user = fail!(from origin,
                         when iceoryx2_bb_posix::user::User::from_self(),
                         with ConfigIterationFailure::UnableToAcquireCurrentUserDetails,
                         "{} since the current user details could not be acquired.", msg);
        match user.details() {
            Some(details) => {
                let mut user_config = *details.config_dir();
                fail!(from origin,
                    when user_config.add_path_entry(&Self::relative_config_path()),
                    with ConfigIterationFailure::TooLongUserConfigDirectory,
                    "{} since the resulting user config directory would be too long.", msg);
                let user_config = fail!(from origin,
                    when FilePath::from_path_and_file(&user_config, &Self::default_config_file_name()),
                    with ConfigIterationFailure::TooLongUserConfigDirectory,
                    "{} since the resulting user config directory would be too long.", msg);

                Ok(user_config)
            }
            None => {
                fail!(from origin,
                      with ConfigIterationFailure::ConfigDirectoryNotAvailable,
                      "{} since the user config directory is not available on the current platform.",
                      msg);
            }
        }
    }

    fn load_global_config_path(
        origin: &str,
        msg: &str,
    ) -> Result<FilePath, ConfigIterationFailure> {
        let mut global_config = GLOBAL_CONFIG_PATH;
        fail!(from origin,
                when global_config.add_path_entry(&Self::relative_config_path()),
                with ConfigIterationFailure::TooLongUserConfigDirectory,
                "{} since the resulting global config directory would be too long.", msg);
        let global_config = fail!(from origin,
                when FilePath::from_path_and_file(&global_config, &Self::default_config_file_name()),
                with ConfigIterationFailure::TooLongUserConfigDirectory,
                "{} since the resulting global config directory would be too long.", msg);

        Ok(global_config)
    }

    fn iterate_over_config_files<F: FnMut(FilePath) -> CallbackProgression>(
        mut callback: F,
    ) -> Result<(), ConfigIterationFailure> {
        let msg = "Unable to consider all possible config file paths";
        let origin = "Config::iterate_over_config_files";

        // prio 1: handle project local config file first
        let local_project_config = Self::default_config_file_path();
        if callback(local_project_config) == CallbackProgression::Stop {
            return Ok(());
        }

        // prio 2: lookup user config file
        if let Ok(user_config) = Self::load_user_config_path(origin, msg)
            && callback(user_config) == CallbackProgression::Stop
        {
            return Ok(());
        }

        // prio 3: lookup global config file
        if let Ok(global_config) = Self::load_global_config_path(origin, msg)
            && callback(global_config) == CallbackProgression::Stop
        {
            return Ok(());
        }

        Ok(())
    }

    /// Loads a configuration from a file. On success it returns a [`Config`] object otherwise a
    /// [`ConfigCreationError`] describing the failure.
    pub fn from_file(config_file: &FilePath) -> Result<Config, ConfigCreationError> {
        let msg = "Failed to create config";
        let mut new_config = Self::default();

        let file = match FileBuilder::new(config_file).open_existing(AccessMode::Read) {
            Ok(file) => file,
            Err(FileOpenError::InsufficientPermissions) => {
                fail!(from new_config,
                      with ConfigCreationError::InsufficientPermissions,
                      "{} since the config file \"{}\" could not be opened due to insufficient permissions.",
                      msg, config_file);
            }
            Err(FileOpenError::FileDoesNotExist) => {
                fail!(from new_config,
                      with ConfigCreationError::ConfigFileDoesNotExist,
                      "{} since the config file \"{}\" does not exist.",
                      msg, config_file);
            }
            Err(e) => {
                fail!(from new_config,
                      with ConfigCreationError::UnableToOpenConfigFile,
                      "{} since the config file \"{}\" could not be open due to an internal error ({:?}).",
                      msg, config_file, e);
            }
        };

        let mut contents = String::new();
        fail!(from new_config, when file.read_to_string(&mut contents),
                with ConfigCreationError::FailedToReadConfigFileContents,
                "{} since the config file contents could not be read.", msg);

        match toml::from_str(&contents) {
            Ok(v) => new_config = v,
            Err(e) => {
                fail!(from new_config, with ConfigCreationError::UnableToDeserializeContents,
                                "{} since the contents could not be deserialized ({}).", msg, e);
            }
        }

        trace!(from new_config, "Loaded.");
        Ok(new_config)
    }

    /// Sets up the global configuration from a file. If the global configuration was already setup
    /// it will print a warning and does not load the file. It returns the [`Config`] when the file
    /// could be successfully loaded otherwise a [`ConfigCreationError`] describing the error.
    pub fn setup_global_config_from_file(
        config_file: &FilePath,
    ) -> Result<&'static Config, ConfigCreationError> {
        if ICEORYX2_CONFIG.is_initialized() {
            return Ok(ICEORYX2_CONFIG.get());
        }

        if !ICEORYX2_CONFIG.set_value(Config::from_file(config_file)?) {
            warn!(
                from ICEORYX2_CONFIG.get(),
                "Configuration already loaded and set up, cannot load another one. This may happen when this function is called from multiple threads."
            );
            return Ok(ICEORYX2_CONFIG.get());
        }

        trace!(from ICEORYX2_CONFIG.get(), "Set as global config.");
        Ok(ICEORYX2_CONFIG.get())
    }

    /// Returns the global configuration. If the global configuration was not yet loaded it will
    /// load a default config by looking it up in the system. First it checks if a project local config file
    /// exists, then if a config file in the user directory exist and then if a global config file exist. If
    /// [`Config::setup_global_config_from_file()`]
    /// is called after this function was called, no file will be loaded since the global default
    /// config was already populated.
    pub fn global_config() -> &'static Config {
        let origin = "Config::global_config()";
        if !ICEORYX2_CONFIG.is_initialized() {
            let mut is_config_file_set = false;
            if let Err(e) = Self::iterate_over_config_files(|config_file_path| {
                match Config::setup_global_config_from_file(&config_file_path) {
                    Ok(_) => {
                        info!(from origin, "Using config file at \"{}\"", config_file_path);
                        is_config_file_set = true;
                        CallbackProgression::Stop
                    }
                    Err(ConfigCreationError::ConfigFileDoesNotExist) => {
                        debug!(from origin, "No config file found at \"{}\"", config_file_path);
                        CallbackProgression::Continue
                    }
                    Err(e) => {
                        warn!(from origin,
                            "Config file found \"{}\" but a failure occurred ({:?}) while reading the content.",
                            config_file_path, e);
                        CallbackProgression::Continue
                    }
                }
            }) {
                warn!(from origin,
                    "A failure occurred ({:?}) while looking up the available config files.", e);
            }

            if !is_config_file_set {
                warn!(from origin,
                    "No config file was loaded, a config with default values will be used.");
                ICEORYX2_CONFIG.set_value(Config::default());
            }
        }
        ICEORYX2_CONFIG.get()
    }
}

#[cfg(test)]
mod multi_user_config_tests {
    use super::*;

    #[test]
    fn file_mode_parses_octal_strings() {
        assert_eq!(FileMode::from_octal_str("1777").unwrap().bits(), 0o1777);
        assert_eq!(FileMode::from_octal_str("0o2770").unwrap().bits(), 0o2770);
        assert_eq!(FileMode::from_octal_str("0660").unwrap().bits(), 0o660);
        assert!(FileMode::from_octal_str("").is_none());
        assert!(FileMode::from_octal_str("9").is_none());
        assert!(FileMode::from_octal_str("17777").is_none());
    }

    #[test]
    fn multi_user_keys_round_trip_through_toml() {
        let toml = r#"
[global.node.security]
mode = "secured"
shared-directory-mode = "2770"
shared-group = "sipwriters"

[global.node.security.iam]
endpoint-mode = "0660"
endpoint-group = "sipwriters"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let security = &config.global.node.security;
        assert!(security.is_multi_user());
        assert_eq!(security.shared_directory_mode.unwrap().bits(), 0o2770);
        assert_eq!(security.iam.endpoint_mode.unwrap().bits(), 0o660);
        assert_eq!(
            security.shared_group.as_ref().unwrap().as_bytes(),
            b"sipwriters"
        );

        let serialized = toml::to_string(&config).unwrap();
        let again: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(again, config);
    }

    #[test]
    fn defaults_are_single_user() {
        let config = Config::default();
        let security = &config.global.node.security;
        assert!(!security.is_multi_user());
        assert!(security.metadata_access().is_owner_only());
        assert!(security.endpoint_access().is_owner_only());
    }

    #[test]
    fn multi_user_settings_are_ignored_in_public_mode() {
        let mut config = Config::default();
        config.global.node.security.shared_directory_mode = FileMode::new(0o1777);
        config.global.node.security.iam.endpoint_mode = FileMode::new(0o666);
        assert!(!config.global.node.security.is_multi_user());
        assert!(
            config
                .global
                .node
                .security
                .metadata_access()
                .is_owner_only()
        );
        assert!(
            config
                .global
                .node
                .security
                .endpoint_access()
                .is_owner_only()
        );
    }

    #[test]
    fn numeric_groups_resolve_without_a_group_database() {
        assert_eq!(resolve_group(&FileName::new(b"3000").unwrap()), Some(3000));
    }
}
