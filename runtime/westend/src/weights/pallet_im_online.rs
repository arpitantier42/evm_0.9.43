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

//! Autogenerated weights for `pallet_im_online`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-05-25, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `bm5`, CPU: `Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("westend-dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/polkadot
// benchmark
// pallet
// --chain=westend-dev
// --steps=50
// --repeat=20
// --pallet=pallet_im_online
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --header=./file_header.txt
// --output=./runtime/westend/src/weights/

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_im_online`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_im_online::WeightInfo for WeightInfo<T> {
	/// Storage: Session Validators (r:1 w:0)
	/// Proof Skipped: Session Validators (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: Session CurrentIndex (r:1 w:0)
	/// Proof Skipped: Session CurrentIndex (max_values: Some(1), max_size: None, mode: Measured)
	/// Storage: ImOnline Keys (r:1 w:0)
	/// Proof: ImOnline Keys (max_values: Some(1), max_size: Some(320002), added: 320497, mode: MaxEncodedLen)
	/// Storage: ImOnline ReceivedHeartbeats (r:1 w:1)
	/// Proof: ImOnline ReceivedHeartbeats (max_values: None, max_size: Some(10021032), added: 10023507, mode: MaxEncodedLen)
	/// Storage: ImOnline AuthoredBlocks (r:1 w:0)
	/// Proof: ImOnline AuthoredBlocks (max_values: None, max_size: Some(56), added: 2531, mode: MaxEncodedLen)
	/// The range of component `k` is `[1, 1000]`.
	/// The range of component `e` is `[1, 100]`.
	fn validate_unsigned_and_then_heartbeat(k: u32, e: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `361 + k * (32 ±0)`
		//  Estimated: `10024497 + e * (35 ±0) + k * (32 ±0)`
		// Minimum execution time: 92_017_000 picoseconds.
		Weight::from_parts(73_188_461, 0)
			.saturating_add(Weight::from_parts(0, 10024497))
			// Standard Error: 316
			.saturating_add(Weight::from_parts(23_357, 0).saturating_mul(k.into()))
			// Standard Error: 3_193
			.saturating_add(Weight::from_parts(392_783, 0).saturating_mul(e.into()))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(1))
			.saturating_add(Weight::from_parts(0, 35).saturating_mul(e.into()))
			.saturating_add(Weight::from_parts(0, 32).saturating_mul(k.into()))
	}
}
