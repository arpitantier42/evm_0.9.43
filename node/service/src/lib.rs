// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Polkadot service. Specialized wrapper over substrate service.

// #![deny(unused_results)]

pub mod chain_spec;
mod grandpa_support;
mod parachains_db;
mod relay_chain_selection;
use fc_db::Backend as FrontierBackend;
// use fc_storage::overrides_handle;
use sc_statement_store::Store as StatementStore;
use polkadot_rpc::EthConfiguration;
use telemetry::{ Telemetry, TelemetryWorker };
use std::sync::Arc;
use std::{ collections::BTreeMap, path::PathBuf, sync::{ Mutex }};
use polkadot_rpc::BackendType;
use std::path::Path;
use fc_rpc_core::types::FilterPool;
use fc_rpc_core::types::FeeHistoryCache;
use fc_rpc::EthTask;
use fc_rpc::OverrideHandle;
use fc_rpc_core::types::FeeHistoryCacheLimit;
use sc_network_sync::SyncingService;
use futures::prelude::*;
use polkadot_runtime::RuntimeApi;
// use node_executor::ExecutorDispatch;
use sc_client_api::BlockchainEvents;
use sc_client_api:: StateBackendFor;

pub mod overseer;

#[cfg(feature = "full-node")]
pub use self::overseer::{OverseerGen, OverseerGenArgs, RealOverseerGen};

#[cfg(test)]
mod tests;

#[cfg(feature = "full-node")]
use {
	grandpa::{self, FinalityProofProvider as GrandpaFinalityProofProvider},
	gum::info,
	polkadot_node_core_approval_voting::{
		self as approval_voting_subsystem, Config as ApprovalVotingConfig,
	},
	polkadot_node_core_av_store::Config as AvailabilityConfig,
	polkadot_node_core_av_store::Error as AvailabilityError,
	polkadot_node_core_candidate_validation::Config as CandidateValidationConfig,
	polkadot_node_core_chain_selection::{
		self as chain_selection_subsystem, Config as ChainSelectionConfig,
	},
	polkadot_node_core_dispute_coordinator::Config as DisputeCoordinatorConfig,
	polkadot_node_network_protocol::{
		peer_set::PeerSetProtocolNames, request_response::ReqProtocolNames,
	},
	sc_client_api::BlockBackend,
	sp_core::traits::SpawnNamed,
	sp_trie::PrefixedMemoryDB,
};
pub fn db_config_dir(config: &Configuration) -> PathBuf {
	config.base_path.config_dir(config.chain_spec.id())
}

use polkadot_node_subsystem_util::database::Database;

#[cfg(feature = "full-node")]
pub use {
	polkadot_overseer::{Handle, Overseer, OverseerConnector, OverseerHandle},
	polkadot_primitives::runtime_api::ParachainHost,
	relay_chain_selection::SelectRelayChain,
	sc_client_api::AuxStore,
	sp_authority_discovery::AuthorityDiscoveryApi,
	sp_blockchain::{HeaderBackend, HeaderMetadata},
	sp_consensus_babe::BabeApi,
};

#[cfg(feature = "full-node")]
use polkadot_node_subsystem::jaeger;

use std::{ time::Duration};

use prometheus_endpoint::Registry;
#[cfg(feature = "full-node")]
use service::KeystoreContainer;
use service::RpcHandlers;
#[cfg(feature = "full-node")]
use telemetry::{ TelemetryWorkerHandle};

// #[cfg(feature = "rococo-native")]
// pub use polkadot_client::RococoExecutorDispatch;

// #[cfg(feature = "westend-native")]
// pub use polkadot_client::WestendExecutorDispatch;

// #[cfg(feature = "kusama-native")]
// pub use polkadot_client::KusamaExecutorDispatch;

#[cfg(feature = "polkadot-native")]
pub use polkadot_client::PolkadotExecutorDispatch;

pub use chain_spec::{ PolkadotChainSpec };
pub use consensus_common::{block_validation::Chain, Proposal, SelectChain};
use frame_benchmarking_cli::SUBSTRATE_REFERENCE_HARDWARE;
use mmr_gadget::MmrGadget;
#[cfg(feature = "full-node")]
pub use polkadot_client::{
	 AbstractClient, Client, ClientHandle, ExecuteWithClient, FullBackend, FullClient,
	RuntimeApiCollection,
};
pub use polkadot_primitives::{Block, BlockId, BlockNumber, CollatorPair, Hash, Id as ParaId};
pub use sc_client_api::{Backend, CallExecutor, ExecutionStrategy};
pub use sc_consensus::{BlockImport, LongestChain};
pub use sc_executor::NativeExecutionDispatch;
use sc_executor::{
	HeapAllocStrategy, NativeElseWasmExecutor, WasmExecutor, DEFAULT_HEAP_ALLOC_STRATEGY,
};
pub use service::{
	config::{DatabaseSource, PrometheusConfig},
	ChainSpec, Configuration, error::Error as SubstrateServiceError, PruningMode, Role, RuntimeGenesis,
	TFullBackend, TFullCallExecutor, TFullClient, TaskManager, TransactionPoolOptions,
};
pub use sp_api::{ApiRef, ConstructRuntimeApi, Core as CoreApi, ProvideRuntimeApi, StateBackend};
pub use sp_runtime::{
	generic,
	traits::{
		self as runtime_traits, BlakeTwo256, Block as BlockT, HashFor, Header as HeaderT, NumberFor,
	},
};

// #[cfg(feature = "kusama-native")]
// pub use {kusama_runtime, kusama_runtime_constants};
#[cfg(feature = "polkadot-native")]
pub use {polkadot_runtime, polkadot_runtime_constants};
// #[cfg(feature = "rococo-native")]
// pub use {rococo_runtime, rococo_runtime_constants};
// #[cfg(feature = "westend-native")]
// pub use {westend_runtime, westend_runtime_constants};

/// Provides the header and block number for a hash.
///
/// Decouples `sc_client_api::Backend` and `sp_blockchain::HeaderBackend`.
pub trait HeaderProvider<Block, Error = sp_blockchain::Error>: Send + Sync + 'static
where
	Block: BlockT,
	Error: std::fmt::Debug + Send + Sync + 'static,
{
	/// Obtain the header for a hash.
	fn header(
		&self,
		hash: <Block as BlockT>::Hash,
	) -> Result<Option<<Block as BlockT>::Header>, Error>;
	/// Obtain the block number for a hash.
	fn number(
		&self,
		hash: <Block as BlockT>::Hash,
	) -> Result<Option<<<Block as BlockT>::Header as HeaderT>::Number>, Error>;
}

impl<Block, T> HeaderProvider<Block> for T
where
	Block: BlockT,
	T: sp_blockchain::HeaderBackend<Block> + 'static,
{
	fn header(
		&self,
		hash: Block::Hash,
	) -> sp_blockchain::Result<Option<<Block as BlockT>::Header>> {
		<Self as sp_blockchain::HeaderBackend<Block>>::header(self, hash)
	}
	fn number(
		&self,
		hash: Block::Hash,
	) -> sp_blockchain::Result<Option<<<Block as BlockT>::Header as HeaderT>::Number>> {
		<Self as sp_blockchain::HeaderBackend<Block>>::number(self, hash)
	}
}

/// Decoupling the provider.
///
/// Mandated since `trait HeaderProvider` can only be
/// implemented once for a generic `T`.
pub trait HeaderProviderProvider<Block>: Send + Sync + 'static
where
	Block: BlockT,
{
	type Provider: HeaderProvider<Block> + 'static;

	fn header_provider(&self) -> &Self::Provider;
}

impl<Block, T> HeaderProviderProvider<Block> for T
where
	Block: BlockT,
	T: sc_client_api::Backend<Block> + 'static,
{
	type Provider = <T as sc_client_api::Backend<Block>>::Blockchain;

	fn header_provider(&self) -> &Self::Provider {
		self.blockchain()
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error(transparent)]
	Io(#[from] std::io::Error),

	#[error(transparent)]
	AddrFormatInvalid(#[from] std::net::AddrParseError),

	#[error(transparent)]
	Sub(#[from] SubstrateServiceError),

	#[error(transparent)]
	Blockchain(#[from] sp_blockchain::Error),

	#[error(transparent)]
	Consensus(#[from] consensus_common::Error),

	#[error("Failed to create an overseer")]
	Overseer(#[from] polkadot_overseer::SubsystemError),

	#[error(transparent)]
	Prometheus(#[from] prometheus_endpoint::PrometheusError),

	#[error(transparent)]
	Telemetry(#[from] telemetry::Error),

	#[error(transparent)]
	Jaeger(#[from] polkadot_node_subsystem::jaeger::JaegerError),

	#[cfg(feature = "full-node")]
	#[error(transparent)]
	Availability(#[from] AvailabilityError),

	#[error("Authorities require the real overseer implementation")]
	AuthoritiesRequireRealOverseer,

	#[cfg(feature = "full-node")]
	#[error("Creating a custom database is required for validators")]
	DatabasePathRequired,

	#[cfg(feature = "full-node")]
	#[error("Expected at least one of polkadot, kusama, or rococo runtime feature")]
	NoRuntime,
}

/// Can be called for a `Configuration` to identify which network the configuration targets.
pub trait IdentifyVariant {
	/// Returns if this is a configuration for the `Polkadot` network.
	fn is_polkadot(&self) -> bool;

	/// Returns if this is a configuration for the `Kusama` network.
	// fn is_kusama(&self) -> bool;

	/// Returns if this is a configuration for the `Westend` network.
	// fn is_westend(&self) -> bool;

	/// Returns if this is a configuration for the `Rococo` network.
	// fn is_rococo(&self) -> bool;

	/// Returns if this is a configuration for the `Wococo` test network.
	fn is_wococo(&self) -> bool;

	/// Returns if this is a configuration for the `Versi` test network.
	fn is_versi(&self) -> bool;

	/// Returns true if this configuration is for a development network.
	fn is_dev(&self) -> bool;
}

impl IdentifyVariant for Box<dyn ChainSpec> {
	fn is_polkadot(&self) -> bool {
		self.id().starts_with("polkadot") || self.id().starts_with("dot")
	}
	// fn is_kusama(&self) -> bool {
	// 	self.id().starts_with("kusama") || self.id().starts_with("ksm")
	// }
	// fn is_westend(&self) -> bool {
	// 	self.id().starts_with("westend") || self.id().starts_with("wnd")
	// }
	// fn is_rococo(&self) -> bool {
	// 	self.id().starts_with("rococo") || self.id().starts_with("rco")
	// }
	fn is_wococo(&self) -> bool {
		self.id().starts_with("wococo") || self.id().starts_with("wco")
	}
	fn is_versi(&self) -> bool {
		self.id().starts_with("versi") || self.id().starts_with("vrs")
	}
	fn is_dev(&self) -> bool {
		self.id().ends_with("dev")
	}
}

#[cfg(feature = "full-node")]
pub fn open_database(db_source: &DatabaseSource) -> Result<Arc<dyn Database>, Error> {
	let parachains_db = match db_source {
		DatabaseSource::RocksDb { path, .. } => parachains_db::open_creating_rocksdb(
			path.clone(),
			parachains_db::CacheSizes::default(),
		)?,
		DatabaseSource::ParityDb { path, .. } => parachains_db::open_creating_paritydb(
			path.parent().ok_or(Error::DatabasePathRequired)?.into(),
			parachains_db::CacheSizes::default(),
		)?,
		DatabaseSource::Auto { paritydb_path, rocksdb_path, .. } => {
			if paritydb_path.is_dir() && paritydb_path.exists() {
				parachains_db::open_creating_paritydb(
					paritydb_path.parent().ok_or(Error::DatabasePathRequired)?.into(),
					parachains_db::CacheSizes::default(),
				)?
			} else {
				parachains_db::open_creating_rocksdb(
					rocksdb_path.clone(),
					parachains_db::CacheSizes::default(),
				)?
			}
		},
		DatabaseSource::Custom { .. } => {
			unimplemented!("No polkadot subsystem db for custom source.");
		},
	};
	Ok(parachains_db)
}

/// Initialize the `Jeager` collector. The destination must listen
/// on the given address and port for `UDP` packets.
#[cfg(any(test, feature = "full-node"))]
fn jaeger_launch_collector_with_agent(
	spawner: impl SpawnNamed,
	config: &Configuration,
	agent: Option<std::net::SocketAddr>,
) -> Result<(), Error> {
	if let Some(agent) = agent {
		let cfg = jaeger::JaegerConfig::builder()
			.agent(agent)
			.named(&config.network.node_name)
			.build();

		jaeger::Jaeger::new(cfg).launch(spawner)?;
	}
	Ok(())
}

#[cfg(feature = "full-node")]
type FullSelectChain = relay_chain_selection::SelectRelayChain<FullBackend>;
#[cfg(feature = "full-node")]
type FullGrandpaBlockImport<RuntimeApi, ExecutorDispatch, ChainSelection = FullSelectChain> =
	grandpa::GrandpaBlockImport<
		FullBackend,
		Block,
		FullClient<RuntimeApi, ExecutorDispatch>,
		ChainSelection,
	>;
#[cfg(feature = "full-node")]
type FullBeefyBlockImport<RuntimeApi, ExecutorDispatch, InnerBlockImport> =
	beefy::import::BeefyBlockImport<
		Block,
		FullBackend,
		FullClient<RuntimeApi, ExecutorDispatch>,
		InnerBlockImport,
	>;

#[cfg(feature = "full-node")]
struct Basics<RuntimeApi, ExecutorDispatch>
where
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi:
		RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
{
	task_manager: TaskManager,
	client: Arc<FullClient<RuntimeApi, ExecutorDispatch>>,
	backend: Arc<FullBackend>,
	keystore_container: KeystoreContainer,
	telemetry: Option<Telemetry>,
}

#[cfg(feature = "full-node")]
fn new_partial_basics<RuntimeApi, ExecutorDispatch>(
	config: &mut Configuration,
	jaeger_agent: Option<std::net::SocketAddr>,
	telemetry_worker_handle: Option<TelemetryWorkerHandle>,
) -> Result<Basics<RuntimeApi, ExecutorDispatch>, Error>
where
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi:
		RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
{
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(move |endpoints| -> Result<_, telemetry::Error> {
			let (worker, mut worker_handle) = if let Some(worker_handle) = telemetry_worker_handle {
				(None, worker_handle)
			} else {
				let worker = TelemetryWorker::new(16)?;
				let worker_handle = worker.handle();
				(Some(worker), worker_handle)
			};
			let telemetry = worker_handle.new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let heap_pages = config
		.default_heap_pages
		.map_or(DEFAULT_HEAP_ALLOC_STRATEGY, |h| HeapAllocStrategy::Static { extra_pages: h as _ });

	let wasm = WasmExecutor::builder()
		.with_execution_method(config.wasm_method)
		.with_onchain_heap_alloc_strategy(heap_pages)
		.with_offchain_heap_alloc_strategy(heap_pages)
		.with_max_runtime_instances(config.max_runtime_instances)
		.with_runtime_cache_size(config.runtime_cache_size)
		.build();

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new_with_wasm_executor(wasm);

	let (client, backend, keystore_container, task_manager) =
		service::new_full_parts::<Block, RuntimeApi, _>(
			&config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		if let Some(worker) = worker {
			task_manager.spawn_handle().spawn(
				"telemetry",
				Some("telemetry"),
				Box::pin(worker.run()),
			);
		}
		telemetry
	});

	jaeger_launch_collector_with_agent(task_manager.spawn_handle(), &*config, jaeger_agent)?;

	Ok(Basics { task_manager, client, backend, keystore_container, telemetry })
}

// changes in new_partial function

#[cfg(feature = "full-node")]
fn new_partial<RuntimeApi, ExecutorDispatch, ChainSelection>(
	config: &mut Configuration,

	Basics { task_manager, backend,
		client, keystore_container, telemetry }: Basics<
		RuntimeApi,
		ExecutorDispatch,
	>,
	select_chain: ChainSelection,
) -> Result<
	service::PartialComponents<
		FullClient<RuntimeApi, ExecutorDispatch>,
		FullBackend,
		ChainSelection,
		sc_consensus::DefaultImportQueue<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
		sc_transaction_pool::FullPool<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
		(
			// impl Fn(
			// 	polkadot_rpc::DenyUnsafe,
			// 	polkadot_rpc::SubscriptionTaskExecutor,
			// ) -> Result<polkadot_rpc::RpcExtension, SubstrateServiceError>,
			(
				babe::BabeBlockImport<
					Block,
					FullClient<RuntimeApi, ExecutorDispatch>,
					FullBeefyBlockImport<
						RuntimeApi,
						ExecutorDispatch,
						FullGrandpaBlockImport<RuntimeApi, ExecutorDispatch, ChainSelection>,
					>,
				>,
				grandpa::LinkHalf<Block, FullClient<RuntimeApi, ExecutorDispatch>, ChainSelection>,
				babe::BabeLink<Block>,
				beefy::BeefyVoterLinks<Block>,
			),
			// grandpa::SharedVoterState,
			babe::BabeWorkerHandle<Block>,
			Option<Telemetry>,
			// FrontierBackend<Block>,
			fc_db::Backend<Block>,

		),
	>,
		SubstrateServiceError,
	>
	where

		RuntimeApi:	 ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
			+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi:
		RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
	ChainSelection: 'static + SelectChain<Block>,
{
	let telemetry = config.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(
			|endpoints| -> Result<_, telemetry::Error> {
				let worker = TelemetryWorker::new(16)?;
				let telemetry = worker.handle().new_telemetry(endpoints);
				Ok((worker, telemetry))
			}
		)
		.transpose()?;

	let executor = service::new_native_or_wasm_executor(&config);

	let (client, backend, keystore_container, task_manager) = service::new_full_parts::<
		Block,
		RuntimeApi,
		_
	>(
		config,
		telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
		executor
	)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});
	let chain_selection = sc_consensus::LongestChain::new(backend.clone());


	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let grandpa_hard_forks = if config.chain_spec.is_polkadot() {
		grandpa_support::kusama_hard_forks()
	}
	else {
		Vec::new()
	};

	let (grandpa_block_import, grandpa_link) = grandpa::block_import_with_authority_set_hard_forks(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		grandpa_hard_forks,
		telemetry.as_ref().map(|x| x.handle()),
	)?;
	let justification_import = grandpa_block_import.clone();

	let (beefy_block_import, beefy_voter_links, beefy_rpc_links) =
		beefy::beefy_block_import_and_links(
			grandpa_block_import,
			backend.clone(),
			client.clone(),
			config.prometheus_registry().cloned(),
		);

	let babe_config = babe::configuration(&*client)?;
	let (block_import, babe_link) =
		babe::block_import(babe_config.clone(), beefy_block_import, client.clone())?;

	let slot_duration = babe_link.config().slot_duration();
	let (import_queue, babe_worker_handle) = babe::import_queue(
		babe_link.clone(),
		block_import.clone(),
		Some(Box::new(justification_import)),
		client.clone(),
		select_chain.clone(),
		move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

			let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration,
				);

			Ok((slot, timestamp))
		},
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	//changes
	let overrides = polkadot_rpc::overrides_handle(client.clone());
	let eth: EthConfiguration = Default::default();
	let frontier_backend = match eth.frontier_backend_type {
		BackendType::KeyValue =>
			FrontierBackend::KeyValue(
				fc_db::kv::Backend::open(
					Arc::clone(&client),
					&config.database,
					&db_config_dir(config)
				)?
			),
		BackendType::Sql => {
			let db_path = db_config_dir(config).join("sql");
			std::fs::create_dir_all(&db_path).expect("failed creating sql db directory");
			let backend = futures::executor
				::block_on(
					fc_db::sql::Backend::new(
						fc_db::sql::BackendConfig::Sqlite(fc_db::sql::SqliteBackendConfig {
							path: Path::new("sqlite:///")
								.join(db_path)
								.join("frontier.db3")
								.to_str()
								.unwrap(),
							create_if_missing: true,
							thread_count: eth.frontier_sql_backend_thread_count,
							cache_size: eth.frontier_sql_backend_cache_size,
						}),
						eth.frontier_sql_backend_pool_size,
						std::num::NonZeroU32::new(eth.frontier_sql_backend_num_ops_timeout),
						overrides.clone()
					)
				)
				.unwrap_or_else(|err| panic!("failed creating sql backend: {:?}", err));
			FrontierBackend::Sql(backend)
		}
	};

	let justification_stream = grandpa_link.justification_stream();
	let shared_authority_set = grandpa_link.shared_authority_set().clone();
	let shared_voter_state = grandpa::SharedVoterState::empty();
	let finality_proof_provider = GrandpaFinalityProofProvider::new_for_service(
		backend.clone(),
		Some(shared_authority_set.clone()),
	);
let backend11=frontier_backend.clone();
	let import_setup = (block_import, grandpa_link, babe_link, beefy_voter_links);
	let rpc_setup = shared_voter_state.clone();

	Ok(service::PartialComponents {
		client,
		backend,
		task_manager,
		keystore_container,
		select_chain,
		import_queue,
		transaction_pool,
		other: (import_setup,babe_worker_handle,telemetry,frontier_backend.into()),
	})
}

//changes

fn spawn_frontier_tasks<RuntimeApi, ExecutorDispatch>(
	task_manager: &TaskManager,
	client: Arc<FullClient<RuntimeApi, ExecutorDispatch>>,
	backend: Arc<FullBackend>,
	frontier_backend: FrontierBackend<Block>,
	filter_pool: Option<FilterPool>,
	overrides: Arc<OverrideHandle<Block>>,
	fee_history_cache: FeeHistoryCache,
	fee_history_cache_limit: FeeHistoryCacheLimit,
	sync: Arc<SyncingService<Block>>,
	pubsub_notification_sinks: Arc<
		fc_mapping_sync::EthereumBlockNotificationSinks<
			fc_mapping_sync::EthereumBlockNotification<Block>,
		>,
	>,
) where
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>,
	RuntimeApi: Send + Sync + 'static,
	RuntimeApi::RuntimeApi:
		RuntimeApiCollection<StateBackend = StateBackendFor<FullBackend, Block>>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,

{
	// Spawn main mapping sync worker background task.
	match frontier_backend {
		fc_db::Backend::KeyValue(b) => {
			task_manager.spawn_essential_handle().spawn(
				"frontier-mapping-sync-worker",
				None,
				fc_mapping_sync::kv::MappingSyncWorker
					::new(
						client.import_notification_stream(),
						Duration::new(6, 0),
						client.clone(),
						backend,

						overrides.clone(),
						Arc::new(b),
						//Arc<FrontierBackend<Block>>,
						3,
						0,
						fc_mapping_sync::SyncStrategy::Normal,
						sync,
						pubsub_notification_sinks
					)
					.for_each(|()| future::ready(()))
			);
		}
		fc_db::Backend::Sql(b) => {
			task_manager.spawn_essential_handle().spawn_blocking(
				"frontier-mapping-sync-worker",
				None,
				fc_mapping_sync::sql::SyncWorker::run(
					client.clone(),
					backend,
					Arc::new(b),
					client.import_notification_stream(),
					fc_mapping_sync::sql::SyncWorkerConfig {
						read_notification_timeout: Duration::from_secs(10),
						check_indexed_blocks_interval: Duration::from_secs(60),
					},
					fc_mapping_sync::SyncStrategy::Parachain,
					sync,
					pubsub_notification_sinks
				)
			);
		}
	}

	// Spawn Frontier EthFilterApi maintenance task.
	if let Some(filter_pool) = filter_pool {
		// Each filter is allowed to stay in the pool for 100 blocks.
		const FILTER_RETAIN_THRESHOLD: u64 = 100;
		task_manager
			.spawn_essential_handle()
			.spawn(
				"frontier-filter-pool",
				Some("frontier"),
				EthTask::filter_pool_task(client.clone(), filter_pool, FILTER_RETAIN_THRESHOLD)
			);
	}
	let overrides = polkadot_rpc::overrides_handle(client.clone());

	// Spawn Frontier FeeHistory cache maintenance task.
	task_manager
		.spawn_essential_handle()
		.spawn(
			"frontier-fee-history",
			Some("frontier"),
			EthTask::fee_history_task(client, overrides, fee_history_cache, fee_history_cache_limit)
		);
}
///

#[cfg(feature = "full-node")]
pub struct NewFull<C> {
	pub task_manager: TaskManager,
	pub client: C,
	pub overseer_handle: Option<Handle>,
	pub network: Arc<sc_network::NetworkService<Block, <Block as BlockT>::Hash>>,
	pub sync_service: Arc<sc_network_sync::SyncingService<Block>>,
	pub rpc_handlers: RpcHandlers,
	pub backend: Arc<FullBackend>,
}

#[cfg(feature = "full-node")]
impl<C> NewFull<C> {
	/// Convert the client type using the given `func`.
	pub fn with_client<NC>(self, func: impl FnOnce(C) -> NC) -> NewFull<NC> {
		NewFull {
			client: func(self.client),
			task_manager: self.task_manager,
			overseer_handle: self.overseer_handle,
			network: self.network,
			sync_service: self.sync_service,
			rpc_handlers: self.rpc_handlers,
			backend: self.backend,
		}
	}
}

/// Is this node a collator?
#[cfg(feature = "full-node")]
#[derive(Clone)]
pub enum IsCollator {
	/// This node is a collator.
	Yes(CollatorPair),
	/// This node is not a collator.
	No,
}

#[cfg(feature = "full-node")]
impl std::fmt::Debug for IsCollator {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
		use sp_core::Pair;
		match self {
			IsCollator::Yes(pair) => write!(fmt, "Yes({})", pair.public()),
			IsCollator::No => write!(fmt, "No"),
		}
	}
}

#[cfg(feature = "full-node")]
impl IsCollator {
	/// Is this a collator?
	fn is_collator(&self) -> bool {
		matches!(self, Self::Yes(_))
	}
}

pub const AVAILABILITY_CONFIG: AvailabilityConfig = AvailabilityConfig {
	col_data: parachains_db::REAL_COLUMNS.col_availability_data,
	col_meta: parachains_db::REAL_COLUMNS.col_availability_meta,
};

/// Create a new full node of arbitrary runtime and executor.
///
/// This is an advanced feature and not recommended for general use. Generally, `build_full` is
/// a better choice.
///
/// `overseer_enable_anyways` always enables the overseer, based on the provided `OverseerGenerator`,
/// regardless of the role the node has. The relay chain selection (longest or disputes-aware) is
/// still determined based on the role of the node. Likewise for authority discovery.
#[cfg(feature = "full-node")]
pub fn new_full<RuntimeApi, ExecutorDispatch, OverseerGenerator>(
	mut config: Configuration,
	is_collator: IsCollator,
	grandpa_pause: Option<(u32, u32)>,
	enable_beefy: bool,
	jaeger_agent: Option<std::net::SocketAddr>,
	telemetry_worker_handle: Option<TelemetryWorkerHandle>,
	program_path: Option<std::path::PathBuf>,
	overseer_enable_anyways: bool,
	overseer_gen: OverseerGenerator,
	overseer_message_channel_capacity_override: Option<usize>,
	_malus_finality_delay: Option<u32>,
	hwbench: Option<sc_sysinfo::HwBench>,
) -> Result<NewFull<Arc<FullClient<RuntimeApi, ExecutorDispatch>>>, Error>
where
	RuntimeApi: ConstructRuntimeApi<Block, FullClient<RuntimeApi, ExecutorDispatch>>
		+ Send
		+ Sync
		+ 'static,
	RuntimeApi::RuntimeApi:
		RuntimeApiCollection<StateBackend = sc_client_api::StateBackendFor<FullBackend, Block>>,
	ExecutorDispatch: NativeExecutionDispatch + 'static,
	OverseerGenerator: OverseerGen,
{
	use polkadot_node_network_protocol::request_response::IncomingRequest;
	use sc_network_common::sync::warp::WarpSyncParams;

	let is_offchain_indexing_enabled = config.offchain_worker.indexing_enabled;
	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks = {
		let mut backoff = sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default();

		// if config.chain_spec.is_rococo() ||
		// 	config.chain_spec.is_wococo() ||
		// 	config.chain_spec.is_versi()
		// {
		// 	// it's a testnet that's in flux, finality has stalled sometimes due
		// 	// to operational issues and it's annoying to slow down block
		// 	// production to 1 block per hour.
		// 	backoff.max_interval = 10;
		// }

		Some(backoff)
	};

	// If not on a known test network, warn the user that BEEFY is still experimental.
	// if enable_beefy &&
	// 	!config.chain_spec.is_rococo() &&
	// 	!config.chain_spec.is_wococo() &&
	// 	!config.chain_spec.is_versi()
	// {
	// 	gum::warn!("BEEFY is still experimental, usage on a production network is discouraged.");
	// }

	let disable_grandpa = config.disable_grandpa;
	let name = config.network.node_name.clone();

	let basics = new_partial_basics::<RuntimeApi, ExecutorDispatch>(
		&mut config,
		jaeger_agent,
		telemetry_worker_handle,
	)?;

	let prometheus_registry = config.prometheus_registry().cloned();

	let overseer_connector = OverseerConnector::default();
	let overseer_handle = Handle::new(overseer_connector.handle());

	let chain_spec = config.chain_spec.cloned_box();

	let keystore = basics.keystore_container.local_keystore();
	let auth_or_collator = role.is_authority() || is_collator.is_collator();
	let pvf_checker_enabled = role.is_authority() && !is_collator.is_collator();

	let select_chain = if auth_or_collator {
		let metrics =
			polkadot_node_subsystem_util::metrics::Metrics::register(prometheus_registry.as_ref())?;

		SelectRelayChain::new_with_overseer(
			basics.backend.clone(),
			overseer_handle.clone(),
			metrics,
			Some(basics.task_manager.spawn_handle()),
		)
	} else {
		SelectRelayChain::new_longest_chain(basics.backend.clone())
	};

	let service::PartialComponents::<_, _, SelectRelayChain<_>, _, _, _> {
	    client,
		backend,
		mut task_manager,
		keystore_container,
		select_chain,
		import_queue,
		transaction_pool,
		other: ( import_setup, babe_worker_handle,  mut telemetry,frontier_backend),
	} = new_partial::<RuntimeApi, ExecutorDispatch, SelectRelayChain<_>>(
		&mut config,
		basics,
		select_chain,
	)?;

	let telemetry = config.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(
			|endpoints| -> Result<_, telemetry::Error> {
				let worker = TelemetryWorker::new(16)?;
				let telemetry = worker.handle().new_telemetry(endpoints);
				Ok((worker, telemetry))
			}
		)
		.transpose()?;
	let mut telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});
	let (grandpa_block_import, grandpa_link) = grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle())
	)?;
	let (block_import, babe_link) = babe::block_import(
		babe::configuration(&*client)?,
		grandpa_block_import,
		client.clone()
	)?;
	let auth_disc_publish_non_global_ips = config.network.allow_non_globals_in_dht;
	let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);
	let slot_duration = babe_link.config().slot_duration();

	let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");

	// Note: GrandPa is pushed before the Polkadot-specific protocols. This doesn't change
	// anything in terms of behaviour, but makes the logs more consistent with the other
	// Substrate nodes.
	let grandpa_protocol_name = grandpa::protocol_standard_name(&genesis_hash, &config.chain_spec);
	net_config.add_notification_protocol(grandpa::grandpa_peers_set_config(
		grandpa_protocol_name.clone(),
	));

	let beefy_gossip_proto_name =
		beefy::gossip_protocol_name(&genesis_hash, config.chain_spec.fork_id());
	// `beefy_on_demand_justifications_handler` is given to `beefy-gadget` task to be run,
	// while `beefy_req_resp_cfg` is added to `config.network.request_response_protocols`.
	let (beefy_on_demand_justifications_handler, beefy_req_resp_cfg) =
		beefy::communication::request_response::BeefyJustifsRequestHandler::new(
			&genesis_hash,
			config.chain_spec.fork_id(),
			client.clone(),
			prometheus_registry.clone(),
		);
	if enable_beefy {
		net_config.add_notification_protocol(beefy::communication::beefy_peers_set_config(
			beefy_gossip_proto_name.clone(),
		));
		net_config.add_request_response_protocol(beefy_req_resp_cfg);
	}

	let peerset_protocol_names =
		PeerSetProtocolNames::new(genesis_hash, config.chain_spec.fork_id());

	{
		use polkadot_network_bridge::{peer_sets_info, IsAuthority};
		let is_authority = if role.is_authority() { IsAuthority::Yes } else { IsAuthority::No };
		for config in peer_sets_info(is_authority, &peerset_protocol_names) {
			net_config.add_notification_protocol(config);
		}
	}

	let req_protocol_names = ReqProtocolNames::new(&genesis_hash, config.chain_spec.fork_id());

	let (pov_req_receiver, cfg) = IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);
	let (chunk_req_receiver, cfg) = IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);
	let (collation_req_receiver, cfg) = IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);
	let (available_data_req_receiver, cfg) =
		IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);
	let (statement_req_receiver, cfg) = IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);
	let (dispute_req_receiver, cfg) = IncomingRequest::get_config_receiver(&req_protocol_names);
	net_config.add_request_response_protocol(cfg);

	let grandpa_hard_forks = if config.chain_spec.is_polkadot() {
		grandpa_support::kusama_hard_forks()
	}
	else {
		Vec::new()
	};

	let warp_sync = Arc::new(grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		import_setup.1.shared_authority_set().clone(),
		grandpa_hard_forks,
	));

	let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
		service::build_network(service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_params: Some(WarpSyncParams::WithProvider(warp_sync)),
		})?;

	if config.offchain_worker.enabled {
		let offchain_workers = Arc::new(sc_offchain::OffchainWorkers::new_with_options(
			client.clone(),
			sc_offchain::OffchainWorkerOptions { enable_http_requests: false },
		));

		// Start the offchain workers to have
		task_manager.spawn_handle().spawn(
			"offchain-notifications",
			None,
			sc_offchain::notification_future(
				config.role.is_authority(),
				client.clone(),
				offchain_workers,
				task_manager.spawn_handle().clone(),
				network.clone(),
			),
		);
	}

	let parachains_db = open_database(&config.database)?;

	let approval_voting_config = ApprovalVotingConfig {
		col_approval_data: parachains_db::REAL_COLUMNS.col_approval_data,
		col_session_data: parachains_db::REAL_COLUMNS.col_session_window_data,
		slot_duration_millis: slot_duration.as_millis() as u64,
	};

	let candidate_validation_config = CandidateValidationConfig {
		artifacts_cache_path: config
			.database
			.path()
			.ok_or(Error::DatabasePathRequired)?
			.join("pvf-artifacts"),
		program_path: match program_path {
			None => std::env::current_exe()?,
			Some(p) => p,
		},
	};

	let chain_selection_config = ChainSelectionConfig {
		col_data: parachains_db::REAL_COLUMNS.col_chain_selection_data,
		stagnant_check_interval: Default::default(),
		stagnant_check_mode: chain_selection_subsystem::StagnantCheckMode::PruneOnly,
	};

	let dispute_coordinator_config = DisputeCoordinatorConfig {
		col_dispute_data: parachains_db::REAL_COLUMNS.col_dispute_coordinator_data,
		col_session_data: parachains_db::REAL_COLUMNS.col_session_window_data,
	};


	// let (grandpa_block_import, grandpa_link) = grandpa::block_import_with_authority_set_hard_forks(
	// 	client.clone(),
	// 	&(client.clone() as Arc<_>),
	// 	select_chain.clone(),
	// 	grandpa_hard_forks,
	// 	telemetry.as_ref().map(|x| x.handle()),
	// )?;
	let pubsub_notification_sinks: fc_mapping_sync::EthereumBlockNotificationSinks<fc_mapping_sync::EthereumBlockNotification<Block>> = Default::default();
		let pubsub_notification_sinks = Arc::new(pubsub_notification_sinks);
		let subscription_task_executor = Arc::new(task_manager.spawn_handle());
		let justification_stream = grandpa_link.justification_stream();
		let shared_authority_set = grandpa_link.shared_authority_set().clone();
		let shared_voter_state = grandpa::SharedVoterState::empty();
		let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));
		let fee_history_cache: FeeHistoryCache = Arc::new(Mutex::new(BTreeMap::new()));
		let fee_history_cache_limit: FeeHistoryCacheLimit = 1000;
		let execute_gas_limit_multiplier = 1000;
		let finality_proof_provider = grandpa::FinalityProofProvider::new_for_service(
			backend.clone(),

			Some(shared_authority_set.clone())
		);
		let overrides = polkadot_rpc::overrides_handle(client.clone());
		let block_data_cache = Arc::new(
			fc_rpc::EthBlockDataCacheTask::new(
				task_manager.spawn_handle(),
				overrides.clone(),
				50,
				50,
				prometheus_registry.clone()
			)
		);
		let service = sync_service.clone();


	let rpc_extensions_builder = {
		let is_authority = false;
		let enable_dev_signer = false;
		let max_past_logs = 10000;
		let chain_spec = config.chain_spec.cloned_box();
		let client = client.clone();
		let keystore = keystore_container.keystore();
		let pool = transaction_pool.clone();
		let network = network.clone();
		let select_chain = select_chain.clone();
		let voter_state = shared_voter_state.clone();

		let pubsub_notification_sinks = pubsub_notification_sinks.clone();
		let rpc_backend = backend.clone();

		let frontier_backend = frontier_backend.clone();
		let fee_history_cache = fee_history_cache.clone();
		let fee_history_cache_limit = fee_history_cache_limit.clone();
		let execute_gas_limit_multiplier = execute_gas_limit_multiplier.clone();
		let overrides = overrides.clone();
		let filter_pool = filter_pool.clone();
		let slot_duration = babe_link.config().slot_duration();



		Box::new(move |deny_unsafe, subscription_executor| {
			let deps = polkadot_rpc::FullDeps {
			 client: client.clone(),
				pool: pool.clone(),
				graph: pool.pool().clone(),
				select_chain: select_chain.clone(),
				chain_spec: chain_spec.cloned_box(),
				deny_unsafe,
				sync: service.clone(),
				babe: polkadot_rpc::BabeDeps {
					keystore: keystore.clone(),
					babe_worker_handle: babe_worker_handle.clone(),

				},
				grandpa: polkadot_rpc::GrandpaDeps {
					shared_voter_state: voter_state.clone(),
					shared_authority_set: shared_authority_set.clone(),
					justification_stream: justification_stream.clone(),
					subscription_executor,
					finality_provider: finality_proof_provider.clone(),
				},

				is_authority,
				enable_dev_signer,
				overrides: overrides.clone(),
				block_data_cache: block_data_cache.clone(),
				network: network.clone(),
				filter_pool: filter_pool.clone(),
				backend:  match frontier_backend.clone(){
					fc_db::Backend::KeyValue(b) => Arc::new(b),
					fc_db::Backend::Sql(b) => Arc::new(b),
				},
				max_past_logs,
				fee_history_cache: fee_history_cache.clone(),
				fee_history_cache_limit: fee_history_cache_limit.clone(),
				execute_gas_limit_multiplier: execute_gas_limit_multiplier.clone(),
				forced_parent_hashes: None,

    beefy: todo!(),
			};

			polkadot_rpc
				::create_full(
					deps,
					subscription_task_executor.clone(),
					pubsub_notification_sinks.clone(),
					rpc_backend.clone()
				)
				.map_err(Into::into)
		})
	};

	let rpc_handlers = service::spawn_tasks(service::SpawnTasksParams {
		config,
		backend: backend.clone(),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		network: network.clone(),
		sync_service: sync_service.clone(),
		rpc_builder: Box::new(rpc_extensions_builder),
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		system_rpc_tx,
		tx_handler_controller,
		telemetry: telemetry.as_mut(),
	})?;
	let backends = backend.clone();

	spawn_frontier_tasks(
		&task_manager,
		client.clone(),
		backends,
		frontier_backend.clone().into(),
		filter_pool.clone(),
		overrides.clone(),
		fee_history_cache.clone(),
		fee_history_cache_limit,
		sync_service.clone(),
		pubsub_notification_sinks.clone()
	);

	if let Some(hwbench) = hwbench {
		sc_sysinfo::print_hwbench(&hwbench);
		if !SUBSTRATE_REFERENCE_HARDWARE.check_hardware(&hwbench) && role.is_authority() {
			log::warn!(
				"⚠️  The hardware does not meet the minimal requirements for role 'Authority' find out more at:\n\
				https://wiki.polkadot.network/docs/maintain-guides-how-to-validate-polkadot#reference-hardware"
			);
		}

		if let Some(ref mut telemetry) = telemetry {
			let telemetry_handle = telemetry.handle();
			task_manager.spawn_handle().spawn(
				"telemetry_hwbench",
				None,
				sc_sysinfo::initialize_hwbench_telemetry(telemetry_handle, hwbench),
			);
		}
	}

	let (block_import, link_half, babe_link, beefy_links) = import_setup;

	let overseer_client = client.clone();
	let spawner = task_manager.spawn_handle();

	let authority_discovery_service = if auth_or_collator || overseer_enable_anyways {
		use futures::StreamExt;
		use sc_network::{Event, NetworkEventStream};

		let authority_discovery_role = if role.is_authority() {
			sc_authority_discovery::Role::PublishAndDiscover(keystore_container.keystore())
		} else {
			// don't publish our addresses when we're not an authority (collator, cumulus, ..)
			sc_authority_discovery::Role::Discover
		};
		let dht_event_stream =
			network.event_stream("authority-discovery").filter_map(|e| async move {
				match e {
					Event::Dht(e) => Some(e),
					_ => None,
				}
			});
		let (worker, service) = sc_authority_discovery::new_worker_and_service_with_config(
			sc_authority_discovery::WorkerConfig {
				publish_non_global_ips: auth_disc_publish_non_global_ips,
				// Require that authority discovery records are signed.
				strict_record_validation: true,
				..Default::default()
			},
			client.clone(),
			network.clone(),
			Box::pin(dht_event_stream),
			authority_discovery_role,
			prometheus_registry.clone(),
		);

		task_manager.spawn_handle().spawn(
			"authority-discovery-worker",
			Some("authority-discovery"),
			Box::pin(worker.run()),
		);
		Some(service)
	} else {
		None
	};

	let overseer_handle = if let Some(authority_discovery_service) = authority_discovery_service {
		let (overseer, overseer_handle) = overseer_gen
			.generate::<service::SpawnTaskHandle, FullClient<RuntimeApi, ExecutorDispatch>>(
				overseer_connector,
				OverseerGenArgs {
					keystore,
					runtime_client: overseer_client.clone(),
					parachains_db,
					network_service: network.clone(),
					sync_service: sync_service.clone(),
					authority_discovery_service,
					pov_req_receiver,
					chunk_req_receiver,
					collation_req_receiver,
					available_data_req_receiver,
					statement_req_receiver,
					dispute_req_receiver,
					registry: prometheus_registry.as_ref(),
					spawner,
					is_collator,
					approval_voting_config,
					availability_config: AVAILABILITY_CONFIG,
					candidate_validation_config,
					chain_selection_config,
					dispute_coordinator_config,
					pvf_checker_enabled,
					overseer_message_channel_capacity_override,
					req_protocol_names,
					peerset_protocol_names,
				},
			)
			.map_err(|e| {
				gum::error!("Failed to init overseer: {}", e);
				e
			})?;
		let handle = Handle::new(overseer_handle.clone());

		{
			let handle = handle.clone();
			task_manager.spawn_essential_handle().spawn_blocking(
				"overseer",
				None,
				Box::pin(async move {
					use futures::{pin_mut, select, FutureExt};

					let forward = polkadot_overseer::forward_events(overseer_client, handle);

					let forward = forward.fuse();
					let overseer_fut = overseer.run().fuse();

					pin_mut!(overseer_fut);
					pin_mut!(forward);

					select! {
						() = forward => (),
						() = overseer_fut => (),
						complete => (),
					}
				}),
			);
		}
		Some(handle)
	} else {
		assert!(
			!auth_or_collator,
			"Precondition congruence (false) is guaranteed by manual checking. qed"
		);
		None
	};

	if role.is_authority() {
		let proposer = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool,
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let client_clone = client.clone();
		let overseer_handle =
			overseer_handle.as_ref().ok_or(Error::AuthoritiesRequireRealOverseer)?.clone();
		let slot_duration = babe_link.config().slot_duration();
		let babe_config = babe::BabeParams {
			keystore: keystore_container.keystore(),
			client: client.clone(),
			select_chain,
			block_import,
			env: proposer,
			sync_oracle: sync_service.clone(),
			justification_sync_link: sync_service.clone(),
			create_inherent_data_providers: move |parent, ()| {
				let client_clone = client_clone.clone();
				let overseer_handle = overseer_handle.clone();

				async move {
					let parachain =
						polkadot_node_core_parachains_inherent::ParachainsInherentDataProvider::new(
							client_clone,
							overseer_handle,
							parent,
						);

					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);

					Ok((slot, timestamp, parachain))
				}
			},
			force_authoring,
			backoff_authoring_blocks,
			babe_link,
			block_proposal_slot_portion: babe::SlotProportion::new(2f32 / 3f32),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		let babe = babe::start_babe(babe_config)?;
		task_manager.spawn_essential_handle().spawn_blocking("babe", None, babe);
	}

	// if the node isn't actively participating in consensus then it doesn't
	// need a keystore, regardless of which protocol we use below.
	let keystore_opt = if role.is_authority() { Some(keystore_container.keystore()) } else { None };

	if enable_beefy {
		let justifications_protocol_name = beefy_on_demand_justifications_handler.protocol_name();
		let network_params = beefy::BeefyNetworkParams {
			network: network.clone(),
			sync: sync_service.clone(),
			gossip_protocol_name: beefy_gossip_proto_name,
			justifications_protocol_name,
			_phantom: core::marker::PhantomData::<Block>,
		};
		let payload_provider = beefy_primitives::mmr::MmrRootProvider::new(client.clone());
		let beefy_params = beefy::BeefyParams {
			client: client.clone(),
			backend: backend.clone(),
			payload_provider,
			runtime: client.clone(),
			key_store: keystore_opt.clone(),
			network_params,
			min_block_delta: if chain_spec.is_wococo() { 4 } else { 8 },
			prometheus_registry: prometheus_registry.clone(),
			links: beefy_links,
			on_demand_justifications_handler: beefy_on_demand_justifications_handler,
		};

		let gadget = beefy::start_beefy_gadget::<_, _, _, _, _, _, _>(beefy_params);

		// Wococo's purpose is to be a testbed for BEEFY, so if it fails we'll
		// bring the node down with it to make sure it is noticed.
		if chain_spec.is_wococo() {
			task_manager
				.spawn_essential_handle()
				.spawn_blocking("beefy-gadget", None, gadget);
		} else {
			task_manager.spawn_handle().spawn_blocking("beefy-gadget", None, gadget);
		}

		if is_offchain_indexing_enabled {
			task_manager.spawn_handle().spawn_blocking(
				"mmr-gadget",
				None,
				MmrGadget::start(
					client.clone(),
					backend.clone(),
					sp_mmr_primitives::INDEXING_PREFIX.to_vec(),
				),
			);
		}
	}

	let config = grandpa::Config {
		// FIXME substrate#1578 make this available through chainspec
		// Grandpa performance can be improved a bit by tuning this parameter, see:
		// https://github.com/paritytech/polkadot/issues/5464
		gossip_duration: Duration::from_millis(1000),
		justification_period: 512,
		name: Some(name),
		observer_enabled: false,
		keystore: keystore_opt,
		local_role: role,
		telemetry: telemetry.as_ref().map(|x| x.handle()),
		protocol_name: grandpa_protocol_name,
	};

	let enable_grandpa = !disable_grandpa;
	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: unlike in substrate we are currently running the full
		// GRANDPA voter protocol for all full nodes (regardless of whether
		// they're validators or not). at this point the full voter should
		// provide better guarantees of block and vote data availability than
		// the observer.

		// add a custom voting rule to temporarily stop voting for new blocks
		// after the given pause block is finalized and restarting after the
		// given delay.
		let mut builder = grandpa::VotingRulesBuilder::default();

		#[cfg(not(feature = "malus"))]
		let _malus_finality_delay = None;

		if let Some(delay) = _malus_finality_delay {
			info!(?delay, "Enabling malus finality delay",);
			builder = builder.add(grandpa::BeforeBestBlockBy(delay));
		};

		let voting_rule = match grandpa_pause {
			Some((block, delay)) => {
				info!(
					block_number = %block,
					delay = %delay,
					"GRANDPA scheduled voting pause set for block #{} with a duration of {} blocks.",
					block,
					delay,
				);

				builder.add(grandpa_support::PauseAfterBlockFor(block, delay)).build()
			},
			None => builder.build(),
		};

		let grandpa_config = grandpa::GrandpaParams {
			config,
			link: link_half,
			network: network.clone(),
			sync: sync_service.clone(),
			voting_rule,
			prometheus_registry: prometheus_registry.clone(),
			shared_voter_state,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		task_manager.spawn_essential_handle().spawn_blocking(
			"grandpa-voter",
			None,
			grandpa::run_grandpa_voter(grandpa_config)?,
		);
	}

	network_starter.start_network();

	Ok(NewFull {
		task_manager,
		client,
		overseer_handle,
		network,
		sync_service,
		rpc_handlers,
		backend,
	})
}

#[cfg(feature = "full-node")]
macro_rules! chain_ops {
	($config:expr, $jaeger_agent:expr, $telemetry_worker_handle:expr; $scope:ident, $executor:ident, $variant:ident) => {{
		let telemetry_worker_handle = $telemetry_worker_handle;
		let jaeger_agent = $jaeger_agent;
		let mut config = $config;
		let basics = new_partial_basics::<$scope::RuntimeApi, $executor>(
			config,
			jaeger_agent,
			telemetry_worker_handle,
		)?;

		use ::sc_consensus::LongestChain;
		// use the longest chain selection, since there is no overseer available
		let chain_selection = LongestChain::new(basics.backend.clone());

		let service::PartialComponents { client, backend, import_queue, task_manager, .. } =
			new_partial::<$scope::RuntimeApi, $executor, LongestChain<_, Block>>(
				&mut config,
				basics,
				chain_selection,
			)?;
		Ok((Arc::new(Client::$variant(client)), backend, import_queue, task_manager))
	}};
}

/// Builds a new object suitable for chain operations.
#[cfg(feature = "full-node")]
pub fn new_chain_ops(
	mut config: &mut Configuration,
	jaeger_agent: Option<std::net::SocketAddr>,
) -> Result<
	(
		Arc<Client>,
		Arc<FullBackend>,
		sc_consensus::BasicQueue<Block, PrefixedMemoryDB<BlakeTwo256>>,
		TaskManager,
	),
	Error,
> {
	config.keystore = service::config::KeystoreConfig::InMemory;

	// #[cfg(feature = "rococo-native")]
	// if config.chain_spec.is_rococo() ||
	// 	config.chain_spec.is_wococo() ||
	// 	config.chain_spec.is_versi()
	// {
	// 	return chain_ops!(config, jaeger_agent, None; rococo_runtime, RococoExecutorDispatch, Rococo)
	// }

	// #[cfg(feature = "kusama-native")]
	// if config.chain_spec.is_kusama() {
	// 	return chain_ops!(config, jaeger_agent, None; kusama_runtime, KusamaExecutorDispatch, Kusama)
	// }

	// #[cfg(feature = "westend-native")]
	// if config.chain_spec.is_westend() {
	// 	return chain_ops!(config, jaeger_agent, None; westend_runtime, WestendExecutorDispatch, Westend)
	// }

	#[cfg(feature = "polkadot-native")]
	{
		return chain_ops!(config, jaeger_agent, None; polkadot_runtime, PolkadotExecutorDispatch, Polkadot)
	}

	#[cfg(not(feature = "polkadot-native"))]
	{
		let _ = config;
		let _ = jaeger_agent;

		Err(Error::NoRuntime)
	}
}

/// Build a full node.
///
/// The actual "flavor", aka if it will use `Polkadot`, `Rococo` or `Kusama` is determined based on
/// [`IdentifyVariant`] using the chain spec.
///
/// `overseer_enable_anyways` always enables the overseer, based on the provided `OverseerGenerator`,
/// regardless of the role the node has. The relay chain selection (longest or disputes-aware) is
/// still determined based on the role of the node. Likewise for authority discovery.
#[cfg(feature = "full-node")]
pub fn build_full(
	config: Configuration,
	is_collator: IsCollator,
	grandpa_pause: Option<(u32, u32)>,
	enable_beefy: bool,
	jaeger_agent: Option<std::net::SocketAddr>,
	telemetry_worker_handle: Option<TelemetryWorkerHandle>,
	overseer_enable_anyways: bool,
	overseer_gen: impl OverseerGen,
	overseer_message_channel_override: Option<usize>,
	malus_finality_delay: Option<u32>,
	hwbench: Option<sc_sysinfo::HwBench>,
) -> Result<NewFull<Client>, Error> {
	// #[cfg(feature = "rococo-native")]
	// if config.chain_spec.is_rococo() ||
	// 	config.chain_spec.is_wococo() ||
	// 	config.chain_spec.is_versi()
	// {
	// 	return new_full::<rococo_runtime::RuntimeApi, RococoExecutorDispatch, _>(
	// 		config,
	// 		is_collator,
	// 		grandpa_pause,
	// 		enable_beefy,
	// 		jaeger_agent,
	// 		telemetry_worker_handle,
	// 		None,
	// 		overseer_enable_anyways,
	// 		overseer_gen,
	// 		overseer_message_channel_override,
	// 		malus_finality_delay,
	// 		hwbench,
	// 	)
	// 	.map(|full| full.with_client(Client::Rococo))
	// }

	// #[cfg(feature = "kusama-native")]
	// if config.chain_spec.is_kusama() {
	// 	return new_full::<kusama_runtime::RuntimeApi, KusamaExecutorDispatch, _>(
	// 		config,
	// 		is_collator,
	// 		grandpa_pause,
	// 		enable_beefy,
	// 		jaeger_agent,
	// 		telemetry_worker_handle,
	// 		None,
	// 		overseer_enable_anyways,
	// 		overseer_gen,
	// 		overseer_message_channel_override,
	// 		malus_finality_delay,
	// 		hwbench,
	// 	)
	// 	.map(|full| full.with_client(Client::Kusama))
	// }

	// #[cfg(feature = "westend-native")]
	// if config.chain_spec.is_westend() {
	// 	return new_full::<westend_runtime::RuntimeApi, WestendExecutorDispatch, _>(
	// 		config,
	// 		is_collator,
	// 		grandpa_pause,
	// 		enable_beefy,
	// 		jaeger_agent,
	// 		telemetry_worker_handle,
	// 		None,
	// 		overseer_enable_anyways,
	// 		overseer_gen,
	// 		overseer_message_channel_override,
	// 		malus_finality_delay,
	// 		hwbench,
	// 	)
	// 	.map(|full| full.with_client(Client::Westend))
	// }

	#[cfg(feature = "polkadot-native")]
	{
		return new_full::<polkadot_runtime::RuntimeApi, PolkadotExecutorDispatch, _>(
			config,
			is_collator,
			grandpa_pause,
			enable_beefy,
			jaeger_agent,
			telemetry_worker_handle,
			None,
			overseer_enable_anyways,
			overseer_gen,
			overseer_message_channel_override.map(|capacity| {
				gum::warn!("Channel capacity should _never_ be tampered with on polkadot!");
				capacity
			}),
			malus_finality_delay,
			hwbench,
		)
		.map(|full| full.with_client(Client::Polkadot))
	}

	#[cfg(not(feature = "polkadot-native"))]
	{
		let _ = config;
		let _ = is_collator;
		let _ = grandpa_pause;
		let _ = enable_beefy;
		let _ = jaeger_agent;
		let _ = telemetry_worker_handle;
		let _ = overseer_enable_anyways;
		let _ = overseer_gen;
		let _ = overseer_message_channel_override;
		let _ = malus_finality_delay;
		let _ = hwbench;

		Err(Error::NoRuntime)
	}
}

/// Reverts the node state down to at most the last finalized block.
///
/// In particular this reverts:
/// - `ApprovalVotingSubsystem` data in the parachains-db;
/// - `ChainSelectionSubsystem` data in the parachains-db;
/// - Low level Babe and Grandpa consensus data.
#[cfg(feature = "full-node")]
pub fn revert_backend(
	client: Arc<Client>,
	backend: Arc<FullBackend>,
	blocks: BlockNumber,
	config: Configuration,
) -> Result<(), Error> {
	let best_number = client.info().best_number;
	let finalized = client.info().finalized_number;
	let revertible = blocks.min(best_number - finalized);

	if revertible == 0 {
		return Ok(())
	}

	let number = best_number - revertible;
	let hash = client.block_hash_from_id(&BlockId::Number(number))?.ok_or(
		sp_blockchain::Error::Backend(format!(
			"Unexpected hash lookup failure for block number: {}",
			number
		)),
	)?;

	let parachains_db = open_database(&config.database)
		.map_err(|err| sp_blockchain::Error::Backend(err.to_string()))?;

	revert_approval_voting(parachains_db.clone(), hash)?;
	revert_chain_selection(parachains_db, hash)?;
	// Revert Substrate consensus related components
	client.execute_with(RevertConsensus { blocks, backend })?;

	Ok(())
}

fn revert_chain_selection(db: Arc<dyn Database>, hash: Hash) -> sp_blockchain::Result<()> {
	let config = chain_selection_subsystem::Config {
		col_data: parachains_db::REAL_COLUMNS.col_chain_selection_data,
		stagnant_check_interval: chain_selection_subsystem::StagnantCheckInterval::never(),
		stagnant_check_mode: chain_selection_subsystem::StagnantCheckMode::PruneOnly,
	};

	let chain_selection = chain_selection_subsystem::ChainSelectionSubsystem::new(config, db);

	chain_selection
		.revert_to(hash)
		.map_err(|err| sp_blockchain::Error::Backend(err.to_string()))
}

fn revert_approval_voting(db: Arc<dyn Database>, hash: Hash) -> sp_blockchain::Result<()> {
	let config = approval_voting_subsystem::Config {
		col_approval_data: parachains_db::REAL_COLUMNS.col_approval_data,
		col_session_data: parachains_db::REAL_COLUMNS.col_session_window_data,
		slot_duration_millis: Default::default(),
	};

	let approval_voting = approval_voting_subsystem::ApprovalVotingSubsystem::with_config(
		config,
		db,
		Arc::new(sc_keystore::LocalKeystore::in_memory()),
		Box::new(consensus_common::NoNetwork),
		approval_voting_subsystem::Metrics::default(),
	);

	approval_voting
		.revert_to(hash)
		.map_err(|err| sp_blockchain::Error::Backend(err.to_string()))
}

struct RevertConsensus {
	blocks: BlockNumber,
	backend: Arc<FullBackend>,
}

impl ExecuteWithClient for RevertConsensus {
	type Output = sp_blockchain::Result<()>;

	fn execute_with_client<Client, Api, Backend>(self, client: Arc<Client>) -> Self::Output
	where
		<Api as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
		Backend: sc_client_api::Backend<Block> + 'static,
		Backend::State: sp_api::StateBackend<BlakeTwo256>,
		Api: polkadot_client::RuntimeApiCollection<StateBackend = Backend::State>,
		Client: AbstractClient<Block, Backend, Api = Api> + 'static,
	{
		// Revert consensus-related components.
		// The operations are not correlated, thus call order is not relevant.
		babe::revert(client.clone(), self.backend, self.blocks)?;
		grandpa::revert(client, self.blocks)?;
		Ok(())
	}
}
