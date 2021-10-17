use cosmwasm_std::{
     CanonicalAddr,  HumanAddr, ReadonlyStorage, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage,
    ReadonlyPrefixedStorage,
};
// use rust_decimal::Decimal;
use crate::constants::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::viewing_key::ViewingKey;
use secret_toolkit::incubator::generational_store::Index;

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
    pub entropy: Vec<u8>,
    pub seed: Vec<u8>,
    pub duration: u64,
    pub start_time: u64,
    pub end_time: u64,
}
//Testing
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LotteryEntries{
    pub user_address: HumanAddr,
    pub amount:Uint128,
    pub entry_time:u64,
}


//Append store
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LastLotteryResults {
    //winning amount and time
    pub winning_amount:u64, //Append store
    pub time:u64,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct SupplyPool {
    pub total_tokens_staked: Uint128,
    pub total_rewards_returned:Uint128,
    pub triggerer_share:Uint128
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct UserInfo {
    pub amount_delegated: Uint128,
    pub(crate) amount_available_for_withdraw:Uint128,
    //Amount and the time of request
    pub requested_withdraw:Vec<(Uint128,u64)>,
    pub total_won:Uint128,
    pub entry_index:Vec<Index>,

}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct UserWinningHistory{
    //winning amount and rewards
    pub winning_amount:u64, //Append store
    pub time:u64,
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




