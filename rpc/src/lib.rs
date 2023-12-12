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

//! Polkadot-specific RPCs implementation.

#![warn(missing_docs)]

// use std::sync::Arc;
use std::{collections::BTreeMap, sync::Arc};
use jsonrpsee::RpcModule;
use polkadot_primitives::{AccountId, Balance,  BlockNumber, Hash, Nonce};
use sc_client_api::AuxStore;
use sc_consensus_beefy::communication::notification::{
	BeefyBestBlockStream, BeefyVersionedFinalityProofStream,
};
use polkadot_runtime;
pub use sc_rpc_api::DenyUnsafe;
use sp_core::H256;
use polkadot_runtime::{opaque::Block};
use sc_consensus_grandpa::FinalityProofProvider;
pub use sc_rpc::{ SubscriptionTaskExecutor};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SelectChain;
use sp_consensus_babe::BabeApi;
use sc_network::NetworkService;
use sc_network_sync::SyncingService;
use sc_client_api::{
	backend::{ Backend, StateBackend, StorageProvider},
	client::BlockchainEvents,
};
use sp_api::CallApiAt;
use sp_keystore::KeystorePtr;
use txpool_api::TransactionPool;
use sc_transaction_pool::{ChainApi, Pool};
use fc_rpc_core::{types::{FeeHistoryCache, FeeHistoryCacheLimit, FilterPool}, EthApiServer};
use fp_storage::EthereumStorageSchema;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT};
use polkadot_client::RuntimeApiCollection;

/// A type representing all RPC extensions.
pub type RpcExtension = RpcModule<()>;

/// Extra dependencies for BABE.
pub struct BabeDeps {
	/// A handle to the BABE worker for issuing requests.
	pub babe_worker_handle: sc_consensus_babe::BabeWorkerHandle<Block>,
	/// The keystore that manages the keys of the node.
	pub keystore: KeystorePtr,
}
// Frontier
use fc_rpc::{
	EthBlockDataCacheTask, OverrideHandle, RuntimeApiStorageOverride, SchemaV1Override,
	SchemaV2Override, SchemaV3Override, StorageOverride,TxPool
};

/// Dependencies for GRANDPA
pub struct GrandpaDeps<B> {
	/// Voting round info.
	pub shared_voter_state: sc_consensus_grandpa::SharedVoterState,
	/// Authority set info.
	pub shared_authority_set: sc_consensus_grandpa::SharedAuthoritySet<Hash, BlockNumber>,
	/// Receives notifications about justification events from Grandpa.
	pub justification_stream: sc_consensus_grandpa::GrandpaJustificationStream<Block>,
	/// Executor to drive the subscription manager in the Grandpa RPC handler.
	pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
	/// Finality proof provider.
	pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Dependencies for BEEFY
pub struct BeefyDeps {
	/// Receives notifications about finality proof events from BEEFY.
	pub beefy_finality_proof_stream: BeefyVersionedFinalityProofStream<Block>,
	/// Receives notifications about best block events from BEEFY.
	pub beefy_best_block_stream: BeefyBestBlockStream<Block>,
	/// Executor to drive the subscription manager in the BEEFY RPC handler.
	pub subscription_executor: sc_rpc::SubscriptionTaskExecutor,
}

/// Full client dependencies
pub struct FullDeps<C, P, SC, B,A:ChainApi> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// The [`SelectChain`] Strategy
	pub select_chain: SC,
	/// A copy of the chain spec.
	pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
	/// Whether to deny unsafe calls
	pub deny_unsafe: DenyUnsafe,
	/// BABE specific dependencies.
	pub babe: BabeDeps,
	/// GRANDPA specific dependencies.
	pub grandpa: GrandpaDeps<B>,
	/// Shared statement store reference.
	/// BEEFY specific dependencies.

	pub beefy: BeefyDeps,
 /// Graph pool instance.
	/// ////////////
	pub graph: Arc<Pool<A>>,
	/// The Node authority flag
	pub is_authority: bool,
	/// Whether to enable dev signer
	pub enable_dev_signer: bool,
	/// Network service
	pub network: Arc<NetworkService<Block, Hash>>,

   	pub sync: Arc<SyncingService<Block>>,
	/// EthFilterApi pool.
	pub filter_pool: Option<FilterPool>,
	/// Backend.
	pub backend: Arc<dyn fc_db::BackendReader<Block> + Send + Sync>,
	/// Maximum number of logs in a query.
	pub max_past_logs: u32,
	/// Fee history cache.
	pub fee_history_cache: FeeHistoryCache,
	/// Maximum fee history cache size.
	pub fee_history_cache_limit: FeeHistoryCacheLimit,
	/// Ethereum data access overrides.
	pub overrides: Arc<OverrideHandle<Block>>,
	/// Cache for Ethereum block data.
	pub block_data_cache: Arc<EthBlockDataCacheTask<Block>>,
	pub execute_gas_limit_multiplier: u64,
    /// Mandated parent hashes for a given block hash.
	pub forced_parent_hashes: Option<BTreeMap<H256, H256>>,

}
/// Avalailable frontier backend types.
///
#[derive(Debug, Copy, Clone, Default, clap::ValueEnum)]
pub enum BackendType {
	/// Either RocksDb or ParityDb as per inherited from the global backend settings.
	#[default]
	KeyValue,
	/// Sql database with custom log indexing.
	Sql,
}
#[derive(Default)]
//// The ethereum-compatibility configuration used to run a node.
#[derive(Clone, Debug, clap::Parser)]
///ethereum compatibility
pub struct EthConfiguration {
	/// Maximum number of logs in a query.
	#[arg(long, default_value = "10000")]
	pub max_past_logs: u32,

	/// Maximum fee history cache size.
	#[arg(long, default_value = "2048")]
	pub fee_history_limit: u64,

	#[arg(long)]
	pub enable_dev_signer: bool,

	/// The dynamic-fee pallet target gas price set by block author
	#[arg(long, default_value = "1")]
	pub target_gas_price: u64,

	/// Maximum allowed gas limit will be `block.gas_limit * execute_gas_limit_multiplier`
	/// when using eth_call/eth_estimateGas.
	#[arg(long, default_value = "10")]
	pub execute_gas_limit_multiplier: u64,

	/// Size in bytes of the LRU cache for block data.
	#[arg(long, default_value = "50")]
	pub eth_log_block_cache: usize,

	/// Size in bytes of the LRU cache for transactions statuses data.
	#[arg(long, default_value = "50")]
	pub eth_statuses_cache: usize,

	/// Sets the frontier backend type (KeyValue or Sql)
	#[arg(long, value_enum, ignore_case = true, default_value_t = BackendType::default())]
	pub frontier_backend_type: BackendType,

	// Sets the SQL backend's pool size.
	#[arg(long, default_value = "100")]
	pub frontier_sql_backend_pool_size: u32,

	/// Sets the SQL backend's query timeout in number of VM ops.
	#[arg(long, default_value = "10000000")]
	pub frontier_sql_backend_num_ops_timeout: u32,

	/// Sets the SQL backend's auxiliary thread limit.
	#[arg(long, default_value = "4")]
	pub frontier_sql_backend_thread_count: u32,

	/// Sets the SQL backend's query timeout in number of VM ops.
	/// Default value is 200MB.
	#[arg(long, default_value = "209715200")]
	pub frontier_sql_backend_cache_size: u64,

}

pub fn overrides_handle<C, BE>(client: Arc<C>) -> Arc<OverrideHandle<Block>>
where
	C: ProvideRuntimeApi<Block> + StorageProvider<Block, BE> + AuxStore,
	C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError>,
	C: Send + Sync + 'static,
	C::Api: sp_api::ApiExt<Block>
		+ fp_rpc::EthereumRuntimeRPCApi<Block>
	    + fp_rpc::ConvertTransactionRuntimeApi<Block>,
	BE: Backend<Block>  + Send + Sync +'static,
	BE::State: StateBackend<BlakeTwo256>,

{

		let mut overrides_map = BTreeMap::new();
		overrides_map.insert(
			EthereumStorageSchema::V1,
			Box::new(SchemaV1Override::new(client.clone())) as Box<dyn StorageOverride<_>>,
		);
		overrides_map.insert(
			EthereumStorageSchema::V2,
			Box::new(SchemaV2Override::new(client.clone())) as Box<dyn StorageOverride<_>>,
		);
		overrides_map.insert(
			EthereumStorageSchema::V3,
			Box::new(SchemaV3Override::new(client.clone())) as Box<dyn StorageOverride<_>>,
		);

		Arc::new(OverrideHandle {
			schemas: overrides_map,
			fallback: Box::new(RuntimeApiStorageOverride::new(client)),
		})
	}

//Instantiate all RPC extensions.

pub fn create_full<C, P, SC, B,BE,A>(
	deps: FullDeps<C, P, SC, B,A>,
	subscription_task_executor: SubscriptionTaskExecutor,
	pubsub_notification_sinks: Arc<
	fc_mapping_sync::EthereumBlockNotificationSinks<
		fc_mapping_sync::EthereumBlockNotification<Block>,
		>,
	>,
	_backend: Arc<B>,
) -> Result<RpcExtension, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
	    + sc_client_api::BlockBackend<Block>
		+ HeaderBackend<Block>
		+ AuxStore
		+ HeaderMetadata<Block, Error = BlockChainError>
		+ Send
		+ Sync
		+ 'static,
	C::Api: frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
	C::Api: mmr_rpc::MmrRuntimeApi<Block, <Block as sp_runtime::traits::Block>::Hash, BlockNumber>,
	C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
	C::Api: BabeApi<Block>,
	C::Api: BlockBuilder<Block>,
	P: TransactionPool + Sync + Send + 'static,
	SC: SelectChain<Block> + 'static,
	B: sc_client_api::Backend<Block> + Send + Sync + 'static,
	B::State: sc_client_api::StateBackend<sp_runtime::traits::HashFor<Block>>,
	A: sc_transaction_pool::ChainApi,
	C: BlockchainEvents<Block> + 'static,
	C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + StorageProvider<Block, BE>,
	BE: Backend<Block> + 'static,
	C: CallApiAt<Block> + ProvideRuntimeApi<Block>,
	C::Api: RuntimeApiCollection,
	C::Api: fp_rpc::ConvertTransactionRuntimeApi<Block>,
	C::Api: fp_rpc::EthereumRuntimeRPCApi<Block>,
	A: ChainApi<Block = Block> + 'static,
	P: TransactionPool<Block=Block> + 'static,

{
	use frame_rpc_system::{System, SystemApiServer};
	// use mmr_rpc::{Mmr, MmrApiServer};
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use sc_consensus_babe_rpc::{Babe, BabeApiServer};
	use sc_consensus_beefy_rpc::{Beefy, BeefyApiServer};
	use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
	use sc_sync_state_rpc::{SyncState, SyncStateApiServer};
	use fc_rpc::{
		Eth, EthDevSigner, EthFilter, EthFilterApiServer, EthPubSub,
		EthPubSubApiServer, EthSigner, Net, NetApiServer, Web3, Web3ApiServer,
	};

	let mut io = RpcModule::new(());
	let FullDeps { client, pool, select_chain, chain_spec, deny_unsafe, babe, grandpa, beefy,graph,
		is_authority,
		enable_dev_signer,
		network,
        sync,
		filter_pool,
		backend,
		max_past_logs,
		fee_history_cache,
		fee_history_cache_limit,
		overrides,
		block_data_cache,
		execute_gas_limit_multiplier ,
        forced_parent_hashes,} =
		deps;
	let BabeDeps { babe_worker_handle, keystore } = babe;
	let GrandpaDeps {
		shared_voter_state,
		shared_authority_set,
		justification_stream,
		subscription_executor,
		finality_provider,
	} = grandpa;

	// io.merge(StateMigration::new(client.clone(), backend, deny_unsafe).into_rpc())?;
	let mut signers = Vec::new();
	if enable_dev_signer {
		signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);
	}
	io.merge(System::new(client.clone(), pool.clone(), deny_unsafe).into_rpc())?;
	io.merge(TransactionPayment::new(client.clone()).into_rpc())?;
	// io.merge(Mmr::new(client.clone()).into_rpc())?;
	io.merge(
		Babe::new(client.clone(), babe_worker_handle.clone(), keystore, select_chain, deny_unsafe)
			.into_rpc(),
	)?;
	io.merge(
		Grandpa::new(
			subscription_executor,
			shared_authority_set.clone(),
			shared_voter_state,
			justification_stream,
			finality_provider,
		)
		.into_rpc(),
	)?;
	let  pp=pool.clone();
	let  pbp=pool.clone();
	io.merge(
		Eth::new(
		client.clone(),
		pp,
		graph.clone(),
		Some(polkadot_runtime::TransactionConverter),
		sync.clone(),
		signers,
		overrides.clone(),
		backend.clone(),
		// Is authority.
		is_authority,
		block_data_cache.clone(),
		fee_history_cache,
		fee_history_cache_limit,
		execute_gas_limit_multiplier,
		forced_parent_hashes,
	)
	// .replace_config::<EC>()
	.into_rpc(),
)?;

let tx_pool = TxPool::new(client.clone(), graph.clone());

if let Some(filter_pool) = filter_pool {

	io.merge(
		EthFilter::new(
			client.clone(),
			backend,
			tx_pool.clone(),
			filter_pool,
			500_usize, // max stored filters
			max_past_logs,
			block_data_cache,
		)
		.into_rpc(),
	)?;
}

io.merge(
	EthPubSub::new(
		pbp,
		client.clone(),
		sync.clone(),
		subscription_task_executor,
		overrides,
		pubsub_notification_sinks,
	)
	.into_rpc(),
)?;

// io.merge(Contracts::new(client.clone()).into_rpc())?;
io.merge(
	Net::new(
		client.clone(),
		network,
		// Whether to format the `peer_count` response as Hex (default) or not.
		true,
	)
	.into_rpc(),
)?;
	// io.merge(
	// 	SyncState::new(chain_spec, client, shared_authority_set, babe_worker_handle)?.into_rpc(),
	// )?;

	io.merge(
		Beefy::<Block>::new(
			beefy.beefy_finality_proof_stream,
			beefy.beefy_best_block_stream,
			beefy.subscription_executor,
		)?
		.into_rpc(),
	)?;

	// io.merge(Web3::new(client.clone()).into_rpc())?;
	Ok(io)
}
