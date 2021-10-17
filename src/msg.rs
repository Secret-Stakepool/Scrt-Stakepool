use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, HumanAddr, Uint128};

use crate::viewing_key::ViewingKey;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct InitialBalance {
    pub address: HumanAddr,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    pub admin: Option<HumanAddr>,
    pub triggerer: Option<HumanAddr>,
    pub denom: String,
    pub prng_seed: Binary,
    pub validator:String,
    pub unbonding_period:u64,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    //User
    Deposit {
        padding: Option<String>,
    },
    TriggerWithdraw{
        amount: Uint128,
        padding: Option<String>,
    },
    Withdraw {
        amount: Uint128,
        padding: Option<String>,
    },
    Redelegate {
        amount: Uint128,
        padding: Option<String>,
    },

    // Base ERC-20 stuff
    CreateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },



    // Admin
    ChangeAdmin {
        address: HumanAddr,
        padding: Option<String>,
    },
    ChangeTriggerer {
        address: HumanAddr,
        padding: Option<String>,
    },
    ChangeTriggererShare {
        percentage: u64,
        padding: Option<String>,
    },
    ChangeLotteryDuration {
        duration:u64
   },
    ChangeUnbondingTime{
        unbonding_time:u64,
    },

    ChangeValidator {
        address: String
    },

    SetNormalStatus {
    },
    SetStopAllStatus {
    },
    SetStopAllButWithdrawStatus {
    },
    ClaimRewards {},
    TriggeringCostWithdraw {},

}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    // Native
    Deposit {
        status: ResponseStatus,
    },
    Redelegate {
        status: ResponseStatus,
    },
    TriggerWithdraw {
        status: ResponseStatus,
    },
    Withdraw {
        status: ResponseStatus,
    },

    TriggeringCostWithdraw {
        status: ResponseStatus,
    },
    // Base
    Transfer {
        status: ResponseStatus,
    },
    Send {
        status: ResponseStatus,
    },
    Burn {
        status: ResponseStatus,
    },
    RegisterReceive {
        status: ResponseStatus,
    },
    CreateViewingKey {
        key: ViewingKey,
    },
    SetViewingKey {
        status: ResponseStatus,
    },

    // Allowance
    IncreaseAllowance {
        spender: HumanAddr,
        owner: HumanAddr,
        allowance: Uint128,
    },
    DecreaseAllowance {
        spender: HumanAddr,
        owner: HumanAddr,
        allowance: Uint128,
    },
    TransferFrom {
        status: ResponseStatus,
    },
    SendFrom {
        status: ResponseStatus,
    },
    BurnFrom {
        status: ResponseStatus,
    },

    // Mint
    Mint {
        status: ResponseStatus,
    },
    AddMinters {
        status: ResponseStatus,
    },
    RemoveMinters {
        status: ResponseStatus,
    },
    SetMinters {
        status: ResponseStatus,
    },

    // Other
    ChangeAdmin {
        status: ResponseStatus,
    },
    ChangeTriggerer {
        status: ResponseStatus,
    },
    ChangeTriggererShare {
        status: ResponseStatus,
    },
    ChangeValidator{
        status: ResponseStatus,
    },
    ChangeLotteryDuration {
        status: ResponseStatus,
    },
    ChangeUnbondingTime{
        status: ResponseStatus,

    },
    SetContractStatus {
        status: ResponseStatus,
    },
    SetNormalStatus {
        status: ResponseStatus,
    },
    SetStopAllStatus {
        status: ResponseStatus,
    },
    SetStopAllButWithdrawStatus {
        status: ResponseStatus,
    },
    ClaimRewards {
        status: ResponseStatus,
        winner: HumanAddr,
    },
    LotteryWinner {
        status: ResponseStatus,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    //PUBLIC
    LotteryInfo {},

    AvailableForWithdrawl {
        address:HumanAddr,
        current_time:u64,
        key:String
    },

    CurrentRewards {},
    TotalDeposits{},
    PastRecords {},
    PastAllRecords {},

    //AUTHENTICATED
    Balance {
        address: HumanAddr,
        key: String,
    },
    UserPastRecords {
        address:HumanAddr,
        key:String
    },
    UserAllPastRecords {
        address:HumanAddr,
        key:String
    },




}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&HumanAddr>, ViewingKey) {
        match self {
            Self::Balance { address, key } => (vec![address], ViewingKey(key.clone())),
            Self::AvailableForWithdrawl {address,key, .. }=>(vec![address], ViewingKey(key.clone())),
            Self::UserPastRecords {address,key}=>(vec![address], ViewingKey(key.clone())),

            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    LotteryInfo {
        start_time: u64,
        end_time: u64,
    },

    ViewingKeyError {
        msg: String,
    },
    Balance{
        amount: Uint128
    },
    AvailableForWithdrawl{
    amount:Uint128,

},
    TotalRewards {
        rewards: Uint128,
    },

    TotalDeposits{
    deposits:Uint128
    },

    PastRecords {
         past_rewards:Vec<(u64, u64)>
    },


    PastAllRecords {
        past_rewards:Vec<(u64,u64)>
    },


    UserPastRecords {
        winning_history:Vec<(u64,u64)>,
    },
    UserAllPastRecords {
        winning_history:Vec<(u64,u64)>,
    },


}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct CreateViewingKeyResponse {
    pub key: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}
// Take a Vec<u8> and pad it up to a multiple of `block_size`, using spaces at the end.
pub fn space_pad(block_size: usize, message: &mut Vec<u8>) -> &mut Vec<u8> {
    let len = message.len();
    let surplus = len % block_size;
    if surplus == 0 {
        return message;
    }

    let missing = block_size - surplus;
    message.reserve(missing);
    message.extend(std::iter::repeat(b' ').take(missing));
    message
}
