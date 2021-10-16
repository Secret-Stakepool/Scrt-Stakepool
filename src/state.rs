use cosmwasm_std::{
     CanonicalAddr,  HumanAddr, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{singleton, singleton_read, PrefixedStorage,
    ReadonlyPrefixedStorage, ReadonlySingleton, Singleton,
};
// use rust_decimal::Decimal;
use std::any::type_name;
use std::convert::TryFrom;
use crate::constants::*;


use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::utils::{bytes_to_u128, bytes_to_u32};
use crate::viewing_key::ViewingKey;
use serde::de::DeserializeOwned;



// Config
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: HumanAddr,
    pub triggerer: HumanAddr,
    pub triggerer_share_percentage:u64,
    pub denom: String,
    pub prng_seed: Vec<u8>,
    pub contract_address: HumanAddr,
    pub validator:String,
    pub unbonding_time:u64,
    pub is_stopped: bool,
    pub is_stopped_can_withdraw:bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Lottery {
    pub entries: Vec<(CanonicalAddr, Uint128,u64)>,
    pub entropy: Vec<u8>,
    pub seed: Vec<u8>,
    pub duration: u64,
    pub start_time: u64,
    pub end_time: u64,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LastLotteryResults {
    pub past_winners:Vec<String>,
    pub past_number_of_entries: Vec<u64>,
    pub past_total_deposits:Vec<u64>,
    //rewards and timestamp
    pub past_total_rewards:Vec<(u64, u64)>
}
pub fn last_lottery_results<S: Storage>(storage: &mut S) -> Singleton<S, LastLotteryResults> {
    singleton(storage, LAST_LOTTERY_KEY)
}

pub fn last_lottery_results_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, LastLotteryResults> {
    singleton_read(storage, LAST_LOTTERY_KEY)
}


// Viewing Keys

pub fn write_viewing_key<S: Storage>(store: &mut S, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut balance_store = PrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let balance_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.get(owner.as_slice())
}




