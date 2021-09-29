use cosmwasm_std::{Uint128};
use serde::{Deserialize, Serialize};
// use schemars::{JsonSchema};
#[derive(Serialize, Deserialize, Debug)]
pub struct SupplyPool {
    pub total_tokens_staked: Uint128,
    pub total_rewards_returned:Uint128,
    pub triggerer_share:Uint128
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub amount_delegated: Uint128,
    pub(crate) amount_available_for_withdraw:Uint128,
    //Amount and the time of request
    pub requested_withdraw:Vec<(Uint128,u64)>,
    pub winning_history:Vec<(u64,u64)>,
    pub total_won:Uint128
}










