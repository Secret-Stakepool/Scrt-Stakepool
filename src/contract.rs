//Crate Import
use crate::constants::*;
use crate::msg::{HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg, ResponseStatus::Success, ResponseStatus::Failure, space_pad};
use crate::rand::sha_256;
use crate::staking::{stake, get_rewards, undelegate, withdraw_to_winner, redelegate};
use crate::state::{read_viewing_key, write_viewing_key, Config, Lottery, LastLotteryResults, UserWinningHistory, LotteryEntries, UserInfo, SupplyPool};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

//Cosmwasm import
use cosmwasm_std::{
    to_binary, Api, BankMsg, Binary, Coin, CosmosMsg, Env, Extern,
    HandleResponse, HumanAddr, InitResponse, Querier, QueryResult,
    StdError, StdResult, Storage, Uint128, };
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

//secret toolkit import
use secret_toolkit::storage::{TypedStore, TypedStoreMut, AppendStore, AppendStoreMut};
use secret_toolkit::incubator::{GenerationalStore, GenerationalStoreMut, generational_store::Entry};

//Rust functions
use sha2::{Digest, Sha256};
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::{SeedableRng};
use rand_chacha::ChaChaRng;
use std::borrow::Borrow;

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {

    // ensuring that the validator is registered
    let vals = deps.querier.query_validators()?;
    let human_addr_wrap = HumanAddr(msg.validator.clone());
    if !vals.iter().any(|v| v.address == human_addr_wrap) {
        return Err(StdError::generic_err(format!(
            "{} is not in the current validator set",
            msg.validator
        )));
    }

    let admin = msg.admin.unwrap_or(env.message.sender);
    let triggerer = msg.triggerer.unwrap_or(admin.clone());
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>, _>::attach(&mut config_prefixed);
    configstore.store(
        CONFIG_KEY,
        &Config {
            admin,
            triggerer,
            prng_seed: prng_seed_hashed.to_vec(),
            denom: msg.denom,
            contract_address: env.contract.address,
            validator: msg.validator,
            triggerer_share_percentage: 1,
            unbonding_time: msg.unbonding_period,
            is_stopped: false,
            is_stopped_can_withdraw: false,
        })?;

    let duration = 604800u64;
    //Starting first lottery

    let mut lottery_prefixed = PrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &mut deps.storage);
    let mut lottery_store = TypedStoreMut::<Lottery, PrefixedStorage<'_, S>>::attach(&mut lottery_prefixed);
    lottery_store.store(
        LOTTERY_KEY,
        &Lottery {
            entropy: prng_seed_hashed.to_vec(),
            start_time: env.block.time + 0,
            end_time: env.block.time + duration + 0,
            seed: prng_seed_hashed.to_vec(),
            duration,
        },
    )?;

    // Setting Total supply
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    supply_store.store(
        SUPPLY_POOL_KEY,
        &SupplyPool {
            total_tokens_staked: Uint128(0),
            total_rewards_returned: Uint128(0),
            triggerer_share: Uint128(0),
        },
    )?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;

    if config.is_stopped {
        let response = match msg {
            HandleMsg::SetNormalStatus {} => set_normal_status(deps, env),
            HandleMsg::SetStopAllButWithdrawStatus {} => set_stop_all_but_withdraw_status(deps, env),
            HandleMsg::SetStopAllStatus {} => set_stop_all_status(deps, env),

            HandleMsg::Withdraw { amount, .. }
            if config.is_stopped_can_withdraw =>
                {
                    try_withdraw(deps, env, amount)
                }
            HandleMsg::TriggerWithdraw { amount, .. }
            if config.is_stopped_can_withdraw =>
                {
                    trigger_withdraw(deps, env, amount)
                }

            _ => Err(StdError::generic_err(
                "This contract is stopped and this action is not allowed",
            )),
        };
        return pad_response(response);
    }

    let response = match msg {

        //Triggerer
        HandleMsg::ClaimRewards {} => claim_rewards(deps, env),

        // Stakepool's Functions
        HandleMsg::Deposit { .. } => try_deposit(deps, env),
        HandleMsg::Redelegate { amount, .. } => try_redelegate(deps, env, amount),
        HandleMsg::Withdraw { amount, .. } => try_withdraw(deps, env, amount),
        HandleMsg::TriggerWithdraw { amount, .. } => trigger_withdraw(deps, env, amount),

        // Base
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Admin
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::ChangeTriggerer { address, .. } => change_triggerer(deps, env, address),
        HandleMsg::ChangeTriggererShare { percentage, .. } => change_triggerer_share(deps, env, percentage),
        HandleMsg::ChangeLotteryDuration { duration } => change_lottery_duration(deps, env, duration),
        HandleMsg::ChangeUnbondingTime { unbonding_time } => change_unbonding_time(deps, env, unbonding_time),

        HandleMsg::TriggeringCostWithdraw {} => triggering_cost_withdraw(deps, env),

        HandleMsg::ChangeValidator { address } => change_validator(deps, env, address),
        HandleMsg::SetStopAllStatus {} => set_stop_all_status(deps, env),
        HandleMsg::SetStopAllButWithdrawStatus {} => set_stop_all_but_withdraw_status(deps, env),

        _ => Err(StdError::generic_err("Unavailable or unknown action"))
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>
(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::LotteryInfo {} => {
            // query_lottery_info(&deps.storage)
            let lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
            let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, S>>::attach(&lottery_prefixed);
            let lottery: Lottery = lottery_store.load(LOTTERY_KEY)?;
            to_binary(&QueryAnswer::LotteryInfo {
                start_time: lottery.start_time,
                end_time: lottery.end_time,
            })
        }
        QueryMsg::CurrentRewards {} => query_current_rewards(&deps),
        QueryMsg::TotalDeposits {} => query_total_deposit(&deps),
        QueryMsg::PastRecords {} => query_past_records(&deps),
        QueryMsg::PastAllRecords {} => query_all_past_records(&deps),

        _ => authenticated_queries(deps, msg),
    }
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetViewingKey { status: Success })?),
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let prng_seed = config.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::CreateViewingKey { key })?),
    })
}

fn set_normal_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;

    check_if_admin(&config, &env.message.sender)?;
    config.is_stopped_can_withdraw = false;
    config.is_stopped = false;
    let _ = configstore.store(CONFIG_KEY, &config);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetNormalStatus {
            status: Success,
        })?),
    })
}

fn set_stop_all_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;
    check_if_admin(&config, &env.message.sender)?;
    config.is_stopped_can_withdraw = false;
    config.is_stopped = true;
    let _ = configstore.store(CONFIG_KEY, &config);
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetStopAllStatus {
            status: Success,
        })?),
    })
}

fn set_stop_all_but_withdraw_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;

    check_if_admin(&config, &env.message.sender)?;
    config.is_stopped_can_withdraw = true;
    config.is_stopped = true;
    let _ = configstore.store(CONFIG_KEY, &config);
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetStopAllButWithdrawStatus {
            status: Success,
        })?),
    })
}

fn valid_amount(amt: Uint128) -> bool {
    amt >= Uint128(1000000)
}

fn try_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut deposit_amount = Uint128::zero();
    for coin in &env.message.sent_funds {
        if coin.denom == "uscrt" {
            deposit_amount = coin.amount
        } else {
            return Err(StdError::generic_err(
                "Coins send are not Scrt",
            ));
        }
    }
    if !valid_amount(deposit_amount) {
        return Err(StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    // Updating user data
    let mut user_prefixed = PrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &mut deps.storage);
    let mut user_store = TypedStoreMut::<UserInfo, PrefixedStorage<'_, S>>::attach(&mut user_prefixed);
    let mut user =
        user_store.load(env.message.sender.0.as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    let account_balance_state = user.amount_delegated.0;
    if let Some(final_account_balance) = account_balance_state.checked_add(deposit_amount.0) {
        user.amount_delegated = Uint128(final_account_balance);
        user_store.store(env.message.sender.0.as_bytes(), &user)?;
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    // Update lottery entries
    let mut lottery_entries = PrefixedStorage::multilevel(&[LOTTERY_ENTRY_KEY], &mut deps.storage);
    let mut lottery_entries_append = GenerationalStoreMut::<LotteryEntries, PrefixedStorage<S>>::attach_or_create(&mut lottery_entries)?;
    user.entry_index.push(lottery_entries_append.insert(LotteryEntries {
        user_address: env.message.sender,
        amount: deposit_amount,
        entry_time: env.block.time,
    }));

    //Updating Supply Store
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    let mut supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;
    supply_pool.total_tokens_staked += deposit_amount;
    //Querying pending_rewards send back from validator
    let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    if rewards > Uint128(0) {
        supply_pool.total_rewards_returned += rewards;
    }
    supply_store.store(SUPPLY_POOL_KEY, &supply_pool)?;

    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let mut messages: Vec<CosmosMsg> = vec![];
    let validator = config.validator;
    messages.push(stake(&validator, deposit_amount.0));

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Deposit { status: Success })?),
    })
}

// claims the rewards to a random winner
fn claim_rewards<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {

    //checking if claim_rewards can be called
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    check_if_triggerer(&config, &env.message.sender)?;

    let mut lottery_prefixed = PrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &mut deps.storage);
    let mut lottery_store = TypedStoreMut::<Lottery, PrefixedStorage<'_, S>>::attach(&mut lottery_prefixed);
    let mut a_lottery: Lottery = lottery_store.load(LOTTERY_KEY)?;
    validate_end_time(a_lottery.end_time, env.block.time)?;
    validate_start_time(a_lottery.start_time, env.block.time)?;

    // This way every time we call the claim_rewards function we will get a different result.
    // Plus it's going to be pretty hard to predict the exact time of the block, so less chance of cheating
    a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    a_lottery.start_time = &env.block.time + 0;
    a_lottery.end_time = &env.block.time + a_lottery.duration + 0;
    lottery_store.store(LOTTERY_KEY, &a_lottery)?;

    //Computing weights for the lottery
    let lottery_entries_append: GenerationalStore::<LotteryEntries, ReadonlyPrefixedStorage<S>>;
    let lottery_entries = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_ENTRY_KEY], &deps.storage);
    if let Ok(res) = GenerationalStore::<LotteryEntries, ReadonlyPrefixedStorage<S>>::attach(&lottery_entries).unwrap_or(
        Err(StdError::generic_err("Lottery Restarted. Error due to no entries "))
    ) {
        lottery_entries_append = res;
    } else {
        return Ok(HandleResponse {
            messages: vec![],
            log: vec![],
            data: Some(to_binary(&HandleAnswer::ClaimRewards {
                status: Failure,
                winner: HumanAddr("Lottery Restarted. Error due to no entries ".to_string()),
            })?),
        });
    }
    let data = lottery_entries_append;
    if data.iter().count() == 0 {
        return Ok(HandleResponse {
            messages: vec![],
            log: vec![],
            data: Some(to_binary(&HandleAnswer::ClaimRewards {
                status: Failure,
                winner: HumanAddr("Lottery Restarted. Error due to no entries ".to_string()),
            })?),
        });
    }

    //Choosing Winner
    let mut entries: Vec<HumanAddr> = vec![];
    let mut weights: Vec<u128> = vec![];
    let iterator = data.iter().filter(|item| matches!(item, (_, Entry::Occupied { .. })));
    for user_address in iterator {
        let user_address = match user_address.1 {
            Entry::Occupied { generation: _, value } => value,
            _ => panic!("Unexpected result "),
        };
        if a_lottery.end_time <= user_address.entry_time {
            entries.push(user_address.user_address);
            weights.push(0 as u128)
        } else if ((&a_lottery.end_time - user_address.entry_time) / &a_lottery.duration) >= 1 {
            entries.push(user_address.user_address);
            weights.push(user_address.amount.0)
        } else {
            entries.push(user_address.user_address);
            weights.push((user_address.amount.0 / 1000000) * ((((a_lottery.end_time - user_address.entry_time) * 1000000) / a_lottery.duration) as u128))
        }
    }
    //Finding the winner

    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;

    let prng_seed = config.prng_seed;
    let mut hasher = Sha256::new();
    hasher.update(&prng_seed);
    hasher.update(&a_lottery.entropy);
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());
    let mut rng: ChaChaRng = ChaChaRng::from_seed(result);

    if let Err(_err) = WeightedIndex::new(&weights) {
        a_lottery.entropy.extend(&env.block.height.to_be_bytes());
        a_lottery.entropy.extend(&env.block.time.to_be_bytes());

        a_lottery.start_time = &env.block.time + 10;
        a_lottery.end_time = &env.block.time + a_lottery.duration + 10;
        let mut lottery_prefixed = PrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &mut deps.storage);
        let mut lottery_store = TypedStoreMut::<Lottery, PrefixedStorage<'_, S>>::attach(&mut lottery_prefixed);
        lottery_store.store(LOTTERY_KEY, &a_lottery)?;

        return Ok(HandleResponse {
            messages: vec![],
            log: vec![],
            data: Some(to_binary(&HandleAnswer::ClaimRewards {
                status: Failure,
                winner: HumanAddr("NONE!!! All entries had weight zero. Lottery restarted".to_string()),
            })?),
        });
    }

    let dist = WeightedIndex::new(&weights).unwrap();
    let sample = dist.sample(&mut rng);
    let winner_human = entries[sample].clone();

    // restart the lottery after completion of this lottery
    a_lottery.start_time = &env.block.time + 10;
    a_lottery.end_time = &env.block.time + a_lottery.duration + 10;
    let mut lottery_prefixed = PrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &mut deps.storage);
    let mut lottery_store = TypedStoreMut::<Lottery, PrefixedStorage<'_, S>>::attach(&mut lottery_prefixed);
    lottery_store.store(LOTTERY_KEY, &a_lottery)?;

    //Querying pending_rewards send back from validator
    let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();

    //setting current pending rewards
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    let mut supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;
    let mut winning_amount = supply_pool.total_rewards_returned;
    if rewards > Uint128(0) {
        winning_amount = supply_pool.total_rewards_returned + rewards;
    }
    if winning_amount <= Uint128(0) {
        return Ok(HandleResponse {
            messages: vec![],
            log: vec![],
            data: Some(to_binary(&HandleAnswer::ClaimRewards {
                status: Failure,
                winner: HumanAddr("No rewards. Lottery restarted".to_string()),
            })?),
        });
    }
    //1 percent
    let triggerpercentage = config.triggerer_share_percentage;

    let triggershare = Uint128(winning_amount.0 * ((triggerpercentage * 1000000) as u128) / 100000000);

    // this way every time we call the claim_rewards function we will get a different result.
    // Plus it's going to be pretty hard to predict the exact time of the block, so less chance of cheating
    winning_amount = (winning_amount - triggershare).unwrap();
    let validator = config.validator;
    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(withdraw_to_winner(&validator, &env.contract.address));
    supply_pool.total_rewards_returned = Uint128(0);
    supply_pool.triggerer_share = triggershare;
    supply_store.store(SUPPLY_POOL_KEY, &supply_pool)?;

    let mut user_prefixed = PrefixedStorage::multilevel(&[USER_INFO_KEY, winner_human.0.as_bytes()], &mut deps.storage);
    let mut user_store = TypedStoreMut::<UserInfo, PrefixedStorage<'_, S>>::attach(&mut user_prefixed);
    let mut user =
        user_store.load(winner_human.0.as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    user.total_won += winning_amount;
    user.amount_available_for_withdraw += winning_amount;
    user_store.store(winner_human.0.as_bytes(), &user)?;

    let mut user_history = PrefixedStorage::multilevel(&[USER_WINNING_HISTORY_KEY, winner_human.0.as_bytes()], &mut deps.storage);
    let mut user_history_append = AppendStoreMut::attach_or_create(&mut user_history)?;
    user_history_append.push(&UserWinningHistory { winning_amount: winning_amount.0 as u64, time: env.block.time })?;

    let mut last_lottery_result = PrefixedStorage::multilevel(&[LAST_LOTTERY_KEY], &mut deps.storage);
    let mut last_lottery_result_append = AppendStoreMut::attach_or_create(&mut last_lottery_result)?;
    last_lottery_result_append.push(&LastLotteryResults { winning_amount: winning_amount.0 as u64, time: env.block.time })?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ClaimRewards {
            status: Success,
            winner: winner_human,
        })?),
    };

    Ok(res)
}

fn trigger_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    trigger_withdraw_amount: Uint128,
) -> StdResult<HandleResponse> {

    //checking if withdraw is enabled

    let mut user_prefixed = PrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &mut deps.storage);
    let mut user_store = TypedStoreMut::<UserInfo, PrefixedStorage<'_, S>>::attach(&mut user_prefixed);
    let mut user = user_store
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    //Subtracting from user's balance plus updating the lottery
    let account_balance_state = user.amount_delegated.0;
    if let Some(account_balance) = account_balance_state.checked_sub(trigger_withdraw_amount.0) {
        user.amount_delegated = Uint128::from(account_balance);
        user.requested_withdraw.push((trigger_withdraw_amount, env.block.time));
        user_store.store(env.message.sender.0.as_bytes(), &user)?;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            account_balance_state, trigger_withdraw_amount
        )));
    }

    // Updating lottery entries
    let mut temp_withdraw_amount = trigger_withdraw_amount.clone();
    let mut lottery_entries = PrefixedStorage::multilevel(&[LOTTERY_ENTRY_KEY], &mut deps.storage);
    let mut lottery_entries_store = GenerationalStoreMut::<LotteryEntries, PrefixedStorage<S>>::attach_or_create(&mut lottery_entries)?;
    for ind in user.clone().entry_index {
        let entry = lottery_entries_store.get(ind.clone()).unwrap();
        if entry.amount == temp_withdraw_amount {
            temp_withdraw_amount = Uint128(0);
            let _ = lottery_entries_store.remove(ind.clone());
            user.entry_index.retain(|index| index.borrow().clone() != ind);
        } else if entry.amount < temp_withdraw_amount {
            temp_withdraw_amount = (temp_withdraw_amount - entry.amount).unwrap();
            let _ = lottery_entries_store.remove(ind.clone());
            user.entry_index.retain(|index| index.borrow().clone() != ind);
        } else {
            let _ = lottery_entries_store.update(ind, LotteryEntries {
                user_address: entry.user_address,
                amount: (entry.amount - temp_withdraw_amount).unwrap(),
                entry_time: entry.entry_time,
            });
            break;
        }
    }

    //Querying pending_rewards send back from validator
    let pending_rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();

    //updating the reward pool
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    let mut supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;
    supply_pool.total_tokens_staked = (supply_pool.total_tokens_staked - trigger_withdraw_amount).unwrap();
    if pending_rewards > Uint128(0) {
        supply_pool.total_rewards_returned += pending_rewards
    }
    supply_store.store(SUPPLY_POOL_KEY, &supply_pool)?;

    //Asking the validator to undelegate the funds
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let validator = config.validator;
    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(undelegate(&validator, trigger_withdraw_amount));

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TriggerWithdraw { status: Success })?),
    };

    Ok(res)
}

fn try_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    withdraw_amount: Uint128,
) -> StdResult<HandleResponse> {
    //loading configs from storage

    //Checking if withdraw id unavailable
    //Checking if the redeem functionality is enabled

    let contract_balance = deps.querier.query_balance(env.contract.address.borrow(), "uscrt").unwrap().amount;

    // checking the requirements for the withdraw
    let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
    let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, S>>::attach(&user_prefixed);
    let mut user = user_store
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    //checking amount available for withdraw
    let mut available_for_withdraw = Uint128(0);
    let mut results: Vec<(Uint128, u64)> = (user.requested_withdraw).into_iter().map(|(requested_withdraw_triggered, requested_time)|
        if requested_time + config.unbonding_time <= env.block.time && withdraw_amount > available_for_withdraw {
            let remaining = (withdraw_amount - available_for_withdraw).unwrap();
            if requested_withdraw_triggered > remaining {
                let final_amount = (requested_withdraw_triggered - remaining).unwrap();
                available_for_withdraw += remaining;
                (final_amount, requested_time)
            } else if requested_withdraw_triggered == remaining {
                available_for_withdraw += requested_withdraw_triggered;
                (Uint128(0), requested_time)
            } else {
                available_for_withdraw += requested_withdraw_triggered;
                (Uint128(0), requested_time)
            }
        } else {
            (requested_withdraw_triggered, requested_time)
        }
    ).collect();
    results.retain(|(amount, _)| amount != &Uint128(0));

    let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, S>>::attach(&supply_pool_prefixed);
    let supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;

    if withdraw_amount > (contract_balance - supply_pool.total_rewards_returned).unwrap() {
        return Err(StdError::generic_err(" Contract balance not enough. Try Again Please"));
    }
    if withdraw_amount > user.amount_available_for_withdraw + available_for_withdraw {
        return Err(StdError::generic_err("Trying to withdraw more than available"));
    }
    user.requested_withdraw = results;
    user.amount_available_for_withdraw += available_for_withdraw;
    user.amount_available_for_withdraw = (user.amount_available_for_withdraw - withdraw_amount).unwrap();
    let mut user_prefixed = PrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &mut deps.storage);
    let mut user_store = TypedStoreMut::<UserInfo, PrefixedStorage<'_, S>>::attach(&mut user_prefixed);
    user_store.store(env.message.sender.0.as_bytes(), &user)?;

    let mut messages: Vec<CosmosMsg> = vec![];
    let withdraw_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount: withdraw_amount,
    }];

    messages.push(CosmosMsg::Bank(BankMsg::Send {
        from_address: env.contract.address,
        to_address: env.message.sender,
        amount: withdraw_coins,
    }));

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Withdraw { status: Success })?),
    };

    Ok(res)
}

fn triggering_cost_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;

    check_if_triggerer(&config, &env.message.sender)?;

    let contract_balance = deps.querier.query_balance(env.contract.address.borrow(), "uscrt").unwrap().amount;
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    let mut supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;

    if contract_balance < supply_pool.triggerer_share {
        return Err(StdError::generic_err("Contract Balance insufficient"));
    }

    if supply_pool.triggerer_share <= Uint128(0) {
        return Err(StdError::generic_err("Triggerer Share not sufficient"));
    }

    let mut messages: Vec<CosmosMsg> = vec![];
    let withdraw_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount: supply_pool.triggerer_share,
    }];

    supply_pool.triggerer_share = Uint128(0);
    supply_store.store(SUPPLY_POOL_KEY, &supply_pool)?;

    messages.push(CosmosMsg::Bank(BankMsg::Send {
        from_address: env.contract.address,
        to_address: env.message.sender,
        amount: withdraw_coins,
    }));

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TriggeringCostWithdraw { status: Success })?),
    };

    Ok(res)
}

fn try_redelegate<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    redelegation_amount: Uint128,
) -> StdResult<HandleResponse> {

    //updating user data
    let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
    let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, S>>::attach(&user_prefixed);
    let mut user =
        user_store.load(env.message.sender.0.as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    let contract_balance = deps.querier.query_balance(env.contract.address.borrow(), "uscrt").unwrap().amount;
    // let sender_address = deps.api.canonical_address(&env.message.sender)?;

    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;

    //checking amount available for withdraw and it is possible to proceed this request
    let mut amount_available_for_redelegation = Uint128(0);
    let mut results: Vec<(Uint128, u64)> = (user.requested_withdraw).into_iter().map(|(requested_in_trigger, requested_time)|
        if requested_time + config.unbonding_time <= env.block.time && amount_available_for_redelegation < redelegation_amount {
            let remaining_amount = (redelegation_amount - amount_available_for_redelegation).unwrap();
            if requested_in_trigger > remaining_amount {
                let final_amount = (requested_in_trigger - remaining_amount).unwrap();
                amount_available_for_redelegation += remaining_amount;
                (final_amount, requested_time)
            } else if requested_in_trigger == remaining_amount {
                amount_available_for_redelegation += requested_in_trigger;
                (Uint128(0), requested_time)
            } else {
                amount_available_for_redelegation += requested_in_trigger;
                (Uint128(0), requested_time)
            }
        } else {
            (requested_in_trigger, requested_time)
        }
    ).collect();

    results.retain(|(amount, _)| amount != &Uint128(0));

    let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
    let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, S>>::attach(&supply_pool_prefixed);
    let mut supply_pool: SupplyPool = supply_store.load(SUPPLY_POOL_KEY)?;

    if redelegation_amount > amount_available_for_redelegation + user.amount_available_for_withdraw {
        return Err(StdError::generic_err("Amount requested to redelegate less than the amount available for redelegation"));
    }
    if redelegation_amount > (contract_balance - supply_pool.total_rewards_returned).unwrap() {
        return Err(StdError::generic_err(" Contract balance not enough. Try Again later"));
    }

    //update the user info
    user.amount_delegated += redelegation_amount;
    user.requested_withdraw = results;
    user.amount_available_for_withdraw += amount_available_for_redelegation;
    user.amount_available_for_withdraw = (user.amount_available_for_withdraw - redelegation_amount).unwrap();
    let mut user_prefixed = PrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &mut deps.storage);
    let mut user_store = TypedStoreMut::<UserInfo, PrefixedStorage<'_, S>>::attach(&mut user_prefixed);
    user_store.store(env.message.sender.0.as_bytes(), &user)?;

    //Updating Rewards store
    supply_pool.total_tokens_staked += redelegation_amount;
    //Querying pending_rewards send back from validator
    let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    if rewards > Uint128(0) {
        supply_pool.total_rewards_returned += rewards;
    }
    //Updating current_round pending rewards
    let mut supply_pool_prefixed = PrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &mut deps.storage);
    let mut supply_store = TypedStoreMut::<SupplyPool, PrefixedStorage<'_, S>>::attach(&mut supply_pool_prefixed);
    supply_store.store(SUPPLY_POOL_KEY, &supply_pool)?;

    let mut messages: Vec<CosmosMsg> = vec![];
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let validator = config.validator;
    messages.push(stake(&validator, redelegation_amount.0));

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Redelegate { status: Success })?),
    };

    Ok(res)
}

fn is_admin(config: &Config, account: &HumanAddr) -> StdResult<bool> {
    if &config.admin != account {
        return Ok(false);
    }

    Ok(true)
}

fn check_if_admin(config: &Config, account: &HumanAddr) -> StdResult<()> {
    if !is_admin(config, account)? {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

fn is_triggerer(config: &Config, account: &HumanAddr) -> StdResult<bool> {
    if &config.triggerer != account {
        return Ok(false);
    }
    Ok(true)
}

fn check_if_triggerer(config: &Config, account: &HumanAddr) -> StdResult<()> {
    if !is_triggerer(config, account)? {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}

/// validate_end_time returns an error if the lottery ends in the future
fn validate_end_time(end_time: u64, current_time: u64) -> StdResult<()> {
    if current_time <= end_time {
        Err(StdError::generic_err("Lottery end time is in the future"))
    } else {
        Ok(())
    }
}

/// validate_start_time returns an error if the lottery hasn't started
fn validate_start_time(start_time: u64, current_time: u64) -> StdResult<()> {
    if current_time < start_time {
        Err(StdError::generic_err("Lottery start time is in the future"))
    } else {
        Ok(())
    }
}

// fn lottery_adjustment<S: Storage, A: Api, Q: Querier>(
//     deps: &Extern<S, A, Q>,
//     mut withdraw_amount: Uint128,
//     sender_address: CanonicalAddr,
// ) -> Lottery {
//     let lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
//     let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, S>>::attach(&lottery_prefixed);
//     let mut a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
//     let results: Vec<(CanonicalAddr, Uint128, u64)> = (a_lottery.entries).into_iter().map(|(address, mut user_staked_amount, deposit_time)|
//         if address == sender_address {
//             if user_staked_amount == withdraw_amount {
//                 user_staked_amount = Uint128(0);
//                 withdraw_amount = Uint128(0);
//             } else if user_staked_amount < withdraw_amount {
//                 withdraw_amount = (withdraw_amount - user_staked_amount).unwrap();
//                 user_staked_amount = Uint128(0);
//             } else if user_staked_amount > withdraw_amount {
//                 user_staked_amount = (user_staked_amount - withdraw_amount).unwrap();
//             }
//             (address, user_staked_amount, deposit_time)
//         } else {
//             (address, user_staked_amount, deposit_time)
//         }
//     ).collect();
//     a_lottery.entries = results;
//     a_lottery.entries.retain(|(_, amount, _)| amount != &Uint128(0));
//     a_lottery
// }

//---------------------------------------------------------------------QUERY FUNCTIONS----------------------------------------------------------------------

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;

        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_deposit(deps, address),
                QueryMsg::AvailableForWithdrawl { address, current_time, .. } => query_available_for_withdrawl(deps, address, current_time),
                QueryMsg::UserPastRecords { address, .. } => query_user_past_records(deps, address),
                QueryMsg::UserAllPastRecords { address, .. } => query_user_past_all_records(deps, address),

                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

fn query_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
) -> StdResult<Binary> {
    let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, address.0.as_bytes()], &deps.storage);
    let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, S>>::attach(&user_prefixed);
    let user =
        user_store.load(address.0.as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    to_binary(&QueryAnswer::Balance {
        amount: user.amount_delegated,
    })
}

fn query_user_past_records<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
) -> StdResult<Binary> {
    let mut results_vec = vec![];
    let user_history = ReadonlyPrefixedStorage::multilevel(&[USER_WINNING_HISTORY_KEY, address.0.as_bytes()], &deps.storage);

    if let Err(_err) = AppendStore::<'_, UserWinningHistory, ReadonlyPrefixedStorage<'_, S>>::attach(&user_history).unwrap_or(Err(StdError::generic_err("No entries yet"))) {
        return to_binary(&QueryAnswer::UserPastRecords {
            winning_history: results_vec,
        });
    }

    let user_history_append: Result<AppendStore<'_, UserWinningHistory, ReadonlyPrefixedStorage<'_, S>>, cosmwasm_std::StdError> = AppendStore::attach(&user_history).unwrap();
    let data = user_history_append.unwrap();
    let mut number_of_entries = data.len();

    if number_of_entries > 5 {
        number_of_entries = 5
    }

    for i in 0..number_of_entries {
        results_vec.push((data.get_at(data.len() - i - 1).unwrap().winning_amount, data.get_at(data.len() - i - 1).unwrap().time))
    }
    to_binary(&QueryAnswer::UserPastRecords {
        winning_history: results_vec,
    })
}

fn query_user_past_all_records<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
) -> StdResult<Binary> {
    let user_history = ReadonlyPrefixedStorage::multilevel(&[USER_WINNING_HISTORY_KEY, address.0.as_bytes()], &deps.storage);
    let mut results_vec = vec![];
    if let Err(_err) = AppendStore::<'_, UserWinningHistory, ReadonlyPrefixedStorage<'_, S>>::attach(&user_history).unwrap_or(Err(StdError::generic_err("No entries yet"))) {
        return to_binary(&QueryAnswer::UserPastRecords {
            winning_history: results_vec,
        });
    }

    let user_history_append: Result<AppendStore<'_, UserWinningHistory, ReadonlyPrefixedStorage<'_, S>>, cosmwasm_std::StdError> = AppendStore::attach(&user_history).unwrap();
    let data = user_history_append.unwrap();
    let number_of_entries = data.len();

    for i in 0..number_of_entries {
        results_vec.push((data.get_at(i).unwrap().winning_amount, data.get_at(i).unwrap().time))
    }
    to_binary(&QueryAnswer::UserAllPastRecords {
        winning_history: results_vec,
    })
}

fn query_available_for_withdrawl<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
    current_time: u64,
) -> StdResult<Binary> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let contract_balance = deps.querier.query_balance(config.contract_address, "uscrt").unwrap().amount;
    let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, address.0.as_bytes()], &deps.storage);
    let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, S>>::attach(&user_prefixed);
    let user =
        user_store.load(address.0.as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

    //checking amount available for withdraw and it is possible to proceed this request
    let mut amount_available_for_withdraw = Uint128(0);

    for (requested_in_trigger, requested_time) in user.requested_withdraw {
        if (requested_time + config.unbonding_time <= current_time) && amount_available_for_withdraw + requested_in_trigger <= contract_balance {
            amount_available_for_withdraw += requested_in_trigger;
        }
    }
    amount_available_for_withdraw += user.amount_available_for_withdraw;

    to_binary(&QueryAnswer::AvailableForWithdrawl {
        amount: amount_available_for_withdraw,
    })
}

fn query_current_rewards<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    //Getting the pending_rewards
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let pending_rewards = get_rewards(&deps.querier, &config.contract_address).unwrap();
    let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
    let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, S>>::attach(&supply_pool_prefixed);
    let supply_pool = supply_store.load(SUPPLY_POOL_KEY)?;

    let total_rewards = pending_rewards + supply_pool.total_rewards_returned;
    to_binary(&QueryAnswer::TotalRewards {
        rewards: total_rewards,
    })
}

fn query_total_deposit<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    //Getting the pending_rewards
    let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
    let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, S>>::attach(&supply_pool_prefixed);
    let supply_pool = supply_store.load(SUPPLY_POOL_KEY)?;

    to_binary(&QueryAnswer::TotalDeposits {
        deposits: supply_pool.total_tokens_staked,
    })
}

fn query_all_past_records<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let last_lottery_results = ReadonlyPrefixedStorage::multilevel(&[LAST_LOTTERY_KEY], &deps.storage);
    let mut results_vec = vec![];

    if let Err(_err) = AppendStore::<'_, LastLotteryResults, ReadonlyPrefixedStorage<'_, S>>::attach(&last_lottery_results).unwrap_or(Err(StdError::generic_err("No entries yet"))) {
        return to_binary(&QueryAnswer::PastAllRecords {
            past_rewards: results_vec.to_owned(),
        });
    }
    let last_lottery_results_append: Result<AppendStore<'_, LastLotteryResults, ReadonlyPrefixedStorage<'_, S>>, cosmwasm_std::StdError> = AppendStore::attach(&last_lottery_results).unwrap();
    let data = last_lottery_results_append.unwrap();
    let number_of_entries = data.len();

    for i in 0..number_of_entries {
        results_vec.push((data.get_at(i).unwrap().winning_amount, data.get_at(i).unwrap().time))
    }

    to_binary(&QueryAnswer::PastAllRecords {
        past_rewards: results_vec,
    })
}

fn query_past_records<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    //Getting the pending_rewards
    let last_lottery_results = ReadonlyPrefixedStorage::multilevel(&[LAST_LOTTERY_KEY], &deps.storage);
    let mut results_vec = vec![];

    if let Err(_err) = AppendStore::<'_, LastLotteryResults, ReadonlyPrefixedStorage<'_, S>>::attach(&last_lottery_results).unwrap_or(Err(StdError::generic_err("No entries yet"))) {
        return to_binary(&QueryAnswer::PastRecords {
            past_rewards: results_vec.to_owned(),
        });
    }

    let last_lottery_results_append: Result<AppendStore<'_, LastLotteryResults, ReadonlyPrefixedStorage<'_, S>>, cosmwasm_std::StdError> =
        AppendStore::attach(&last_lottery_results).unwrap();
    let data = last_lottery_results_append.unwrap();
    let mut number_of_entries = data.len();

    if number_of_entries > 5 {
        number_of_entries = 5;
    }

    for i in 0..number_of_entries {
        results_vec.push((data.get_at(data.len() - i - 1).unwrap().winning_amount, data.get_at(data.len() - i - 1).unwrap().time))
    }

    to_binary(&QueryAnswer::PastRecords {
        past_rewards: results_vec,
    })
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;

    check_if_admin(&config, &env.message.sender)?;

    config.admin = address;
    configstore.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

fn change_triggerer<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;

    check_if_admin(&config, &env.message.sender)?;

    config.triggerer = address;
    configstore.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeTriggerer { status: Success })?),
    })
}

fn change_validator<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: String,
) -> StdResult<HandleResponse> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;
    check_if_admin(&config, &env.message.sender)?;

    //redelegate all of the

    let validator = config.validator;
    config.validator = address;

    let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
    let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, S>>::attach(&supply_pool_prefixed);
    let supply_pool = supply_store.load(SUPPLY_POOL_KEY)?;

    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(redelegate(&validator, &config.validator, supply_pool.total_tokens_staked));

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeValidator { status: Success })?),
    })
}

fn change_lottery_duration<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    duration: u64,
) -> StdResult<HandleResponse> {
    let config_prefixed = ReadonlyPrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &deps.storage);
    let configstore = TypedStore::<Config, ReadonlyPrefixedStorage<'_, S>>::attach(&config_prefixed);
    let config: Config = configstore.load(CONFIG_KEY)?;
    let _ = check_if_admin(&config, &env.message.sender);

    let mut lottery_prefixed = PrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &mut deps.storage);
    let mut lottery_store = TypedStoreMut::<Lottery, PrefixedStorage<'_, S>>::attach(&mut lottery_prefixed);
    let mut a_lottery = lottery_store.load(LOTTERY_KEY)?;
    a_lottery.duration = duration;
    lottery_store.store(LOTTERY_KEY, &a_lottery)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeLotteryDuration { status: Success })?),
    })
}

fn change_unbonding_time<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    unbonding_time: u64,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;
    check_if_admin(&config, &env.message.sender)?;

    config.unbonding_time = unbonding_time;
    configstore.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeUnbondingTime { status: Success })?),
    })
}

fn change_triggerer_share<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    percenatge: u64,
) -> StdResult<HandleResponse> {
    let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
    let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, S>>::attach(&mut config_prefixed);
    let mut config: Config = configstore.load(CONFIG_KEY)?;
    check_if_admin(&config, &env.message.sender)?;

    config.triggerer_share_percentage = percenatge;
    configstore.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeTriggererShare { status: Success })?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ResponseStatus;
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, Decimal, FullDelegation, Validator, BlockInfo, MessageInfo, ContractInfo};
    use std::convert::TryFrom;

    // Helper functions
    fn init_helper(amount: Option<u128>) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[Coin {
            amount: Uint128(amount.unwrap_or(0)),
            denom: "uscrt".to_string(),
        }]);
        let env = mock_env("admin", &[], 1, 0);
        let validator = "v".to_string();

        deps.querier.update_staking(
            "SECSEC",
            &[Validator {
                address: HumanAddr(validator.clone()),
                commission: Decimal::percent(1),
                max_commission: Decimal::percent(2),
                /// TODO: what units are these (in terms of time)?
                max_change_rate: Decimal::percent(3),
            }],
            &[FullDelegation {
                delegator: Default::default(),
                validator: Default::default(),
                amount: Default::default(),
                can_redelegate: Default::default(),
                accumulated_rewards: Default::default(),
            }],
        );

        let init_msg = InitMsg {
            admin: Option::from(HumanAddr("admin".to_string())),
            triggerer: Option::from(HumanAddr("triggerer".to_string())),
            denom: "uscrt".to_string(),
            prng_seed: Binary::from("I'm Batman".as_bytes()),
            validator,
            unbonding_period: 1815400,
        };

        (init(&mut deps, env, init_msg), deps)
    }

    pub fn mock_env<U: Into<HumanAddr>>(sender: U, sent: &[Coin], height: u64, time: u64) -> Env {
        Env {
            block: BlockInfo {
                height,
                time: time,
                chain_id: "secret-testnet".to_string(),
            },
            message: MessageInfo {
                sender: sender.into(),
                sent_funds: sent.to_vec(),
            },
            contract: ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        }
    }

    fn deposit_helper_function(contact_balance: u128) -> Extern<MockStorage, MockApi, MockQuerier> {
        let (_init_result, mut deps) = init_helper(Some(contact_balance));

        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(500000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Superman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(2000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Spider-man", &[Coin { denom: "uscrt".to_string(), amount: Uint128(3000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Wonder-Women", &[Coin { denom: "uscrt".to_string(), amount: Uint128(4000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Thor", &[Coin { denom: "uscrt".to_string(), amount: Uint128(5000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Captain-America", &[Coin { denom: "uscrt".to_string(), amount: Uint128(2000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Ironman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(3000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Loki", &[Coin { denom: "uscrt".to_string(), amount: Uint128(4000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(500000000) }], 10, 0));

        return deps;
    }

    #[test]
    fn testing_overall_deposit() {
        let deps = deposit_helper_function(0);

        //checking reward store
        let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
        let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&supply_pool_prefixed);
        let supply_pool = supply_store.load(SUPPLY_POOL_KEY).unwrap();
        assert_eq!(supply_pool.total_tokens_staked, Uint128(1023000000));
    }

    #[test]
    fn testing_deposit_with_wrong_denom() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman", &[Coin {
            denom: "bitcoin".to_string(),
            amount: Uint128(1000000),
        }], 10, 0);

        let handlemsg = HandleMsg::Deposit { padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(), StdError::generic_err(
            "Coins send are not Scrt",
        ));
    }

    #[test]
    fn testing_deposit_with_less_than_accepted_amount() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman", &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(999999),
        }], 10, 0);

        let handlemsg = HandleMsg::Deposit { padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(), StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    #[test]
    fn testing_deposit_user_data_update() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman", &[Coin {
            denom: "uscrt".to_string(),

            //add one more zero and it will start giving error
            amount: Uint128::try_from("340282366920938463463374607431768211455").unwrap(),
        }], 10, 0);
        //340282366920938463463374607431768211455 39 Digits u128
        //100000000000000000000000000000000000000 39 Digits u128
        //18446744073709551615 20 digits u64
        //190165060000000  total uscrt in secret Network - 16 digits
        //Total possible in scrt network

        let handlemsg = HandleMsg::Deposit { padding: None };
        let _ = handle(&mut deps, env.clone(), handlemsg);

        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load(env.message.sender.0.as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated, Uint128::try_from("340282366920938463463374607431768211455").unwrap());
    }

    #[test]
    fn testing_deposit_lottery_update() {
        //1)Checking for errors
        let (_init_result, mut _deps) = init_helper(None);
        let _env = mock_env("Batman", &[Coin {
            denom: "uscrt".to_string(),

            //add one more zero and it will start giving error
            amount: Uint128::try_from("10000000").unwrap(),
        }], 10, 0);
    }

    #[test]
    fn testing_deposit_rewards_store() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);

        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(10000000) }], 10, 0));

        let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
        let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&supply_pool_prefixed);
        let supply_pool = supply_store.load(SUPPLY_POOL_KEY).unwrap();
        assert_eq!(supply_pool.total_tokens_staked, Uint128(10000000));
    }

    #[test]
    fn testing_trigger_withdraw() {
        let mut deps = deposit_helper_function(0);
        let res = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(1500000000)).unwrap_err();
        assert_eq!(res, StdError::generic_err(format!(
            "insufficient funds to redeem: balance=1000000000, required=1500000000",
        )));

        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let _a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();

        let _res = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(600000000)).unwrap();

        let env = mock_env("Batman", &[], 10, 0);
        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load(env.message.sender.0.as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated.0, 400000000);
        assert_eq!(user.requested_withdraw.len(), 1);

        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let _a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
    }

    #[test]
    fn testing_withdraw() {
        //1)withdraw more than contract balance
        let (_init_result, mut deps) = init_helper(Some(600000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 0));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(700000000));
        let env = mock_env("Batman", &[], 10, 1814400);
        let response = try_withdraw(&mut deps, env.clone(), Uint128(700000000));
        assert_eq!(response.unwrap_err(), StdError::generic_err(" Contract balance not enough. Try Again Please"));

        //2) Amount available for withdraw is less than withdraw amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 0));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(600000000));
        let env = mock_env("Batman", &[], 10, 1814400);
        let response = try_withdraw(&mut deps, env.clone(), Uint128(700000000));
        assert_eq!(response.unwrap_err(), StdError::generic_err("Trying to withdraw more than available"));

        //2.1
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 0));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(300000000));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 10), Uint128(300000000));
        let env = mock_env("Batman", &[], 10, 1814400);
        let response = try_withdraw(&mut deps, env.clone(), Uint128(600000000));
        assert_eq!(response.unwrap_err(), StdError::generic_err("Trying to withdraw more than available"));

        //checking user
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 0));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(300000000));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(300000000));
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let env = mock_env("Batman", &[], 10, config.unbonding_time);
        let _response = try_withdraw(&mut deps, env.clone(), Uint128(600000000));

        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load(env.message.sender.0.as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated, Uint128(400000000));
        assert_eq!(user.requested_withdraw.len(), 0);

        //message check correct working
    }

    #[test]
    fn testing_redelegate() {
        //Depositing amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 0));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(300000000));
        let _ = trigger_withdraw(&mut deps, mock_env("Batman", &[], 10, 0), Uint128(300000000));
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();

        let env = mock_env("Batman", &[], 10, config.unbonding_time);
        let _response = try_redelegate(&mut deps, env.clone(), Uint128(600000000));

        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, env.message.sender.0.as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load(env.message.sender.0.as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated.0, 1000000000);
        assert_eq!(user.requested_withdraw.len(), 0);

        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let _a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();

        let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
        let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&supply_pool_prefixed);
        let supply_pool = supply_store.load(SUPPLY_POOL_KEY).unwrap();
        assert_eq!(supply_pool.total_tokens_staked.0, 1000000000);
    }

    #[test]
    fn testing_claim_rewards() {
        //Depositing amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 1815401));

        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let _a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        //Computing weights for the lottery

        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let _response = claim_rewards(&mut deps, mock_env("triggerer", &[], 10, config.unbonding_time)).unwrap();

        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, "Batman".as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load("Batman".as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error

        assert_eq!(user.requested_withdraw.len(), 0);
        assert_eq!(user.amount_delegated.0, 1000000000);
    }

    #[test]
    fn test_handle_create_viewing_key() {
        let (init_result, mut deps) = init_helper(None);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[], 0, 0), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let (init_result, mut deps) = init_helper(None);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Set VK
        let handle_msg = HandleMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[], 0, 0), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
                .unwrap(),
        );

        // Set valid VK
        let actual_vk = ViewingKey("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = HandleMsg::SetViewingKey {
            key: actual_vk.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[], 0, 0), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey { status: Success }).unwrap(),
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(actual_vk.check_viewing_key(&saved_vk));
    }

    #[test]
    fn test_handle_change_admin() {
        let (init_result, mut deps) = init_helper(None);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[], 0, 0), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
    }

    //QUERY
    #[test]
    fn test_query_lottery() {
        let (_init_result, deps) = init_helper(None);
        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let query_msg = QueryMsg::LotteryInfo {};
        let query_result = query(&deps, query_msg);

        let (start_height, end_height) = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::LotteryInfo { start_time: start, end_time: end } => (start, end),
            _ => panic!("Unexpected result from handle"),
        };
        assert_eq!(a_lottery.end_time, end_height);
        assert_eq!(a_lottery.start_time, start_height);
    }

    #[test]
    fn test_query_total_deposit() {
        let deps = deposit_helper_function(0);
        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let _a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _res: QueryAnswer = from_binary(&query_total_deposit(&deps).unwrap()).unwrap();
    }

    #[test]
    fn test_query_past_results() {
        let mut deps = deposit_helper_function(0);
        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();

        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 2);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 3);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 4);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 5);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 6);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let _env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 7);
        let lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        let env = mock_env("triggerer", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, lottery.end_time * 8);
        let _res = claim_rewards(&mut deps, env);

        let _res: QueryAnswer = from_binary(&query_past_records(&deps).unwrap()).unwrap();
    }

    // Query tests
    #[test]
    fn test_authenticated_queries() {
        let (_init_result, _deps) = init_helper(None);
        let _env = mock_env("sefi", &[], 601, 0);

        let mut deps = deposit_helper_function(0);

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: HumanAddr("Batman".to_string()),
            key: "no_vk_yet".to_string(),
        };
        let _query_result: QueryAnswer = from_binary(&query(&deps, no_vk_yet_query_msg).unwrap()).unwrap();
        // println!("{:?}",query_result);

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "heheeehe".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("Batman", &[], 601, 0), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: HumanAddr("Batman".to_string()),
            key: vk.0,
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128(1000000000));

        let wrong_vk_query_msg = QueryMsg::Balance {
            address: HumanAddr("Batman".to_string()),
            key: "wrong_vk".to_string(),
        };
        let _query_result: QueryAnswer = from_binary(&query(&deps, wrong_vk_query_msg).unwrap()).unwrap();
        // print!("{:?}",query_result);
    }

    #[test]
    fn query_available_for_withdraw() {
        //Contract balance > than
        let mut deps = deposit_helper_function(1000000000);
        let env = mock_env("Batman", &[], 0, 0);
        let _ = trigger_withdraw(&mut deps, env.clone(), Uint128(300000000));
        let _ = trigger_withdraw(&mut deps, env, Uint128(700000000));

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "heheeehe".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("Batman", &[], 601, 0), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::AvailableForWithdrawl {
            address: HumanAddr("Batman".to_string()),
            current_time: 1819406,
            key: vk.0,
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let _balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::AvailableForWithdrawl { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        // println!("The balance is {:?}", balance)
    }

    #[test]
    fn query_user_past_records() {
        //Contract balance > than
        let mut deps = deposit_helper_function(1000000000);
        let env = mock_env("triggerer", &[], 0, 6100);
        let _ = claim_rewards(&mut deps, env.clone());
        //  println!("The winner is {:?}",winner);

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "heheeehe".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("Batman", &[], 601, 0), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::UserPastRecords {
            address: HumanAddr("Batman".to_string()),
            key: vk.0.clone(),
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let _results: QueryAnswer = from_binary(&query_response).unwrap();
        // println!("The balance is {:?}", results);

        let query_balance_msg = QueryMsg::PastAllRecords {};

        let query_response = query(&deps, query_balance_msg).unwrap();
        let _results: QueryAnswer = from_binary(&query_response).unwrap();
        // println!("The balance is {:?}", results);
    }

    #[test]
    fn test_change_admin_triggerer() {
        //Contract balance > than
        let mut deps = deposit_helper_function(1000000000);

        let env = mock_env("non-admin", &[], 600, 0);
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();

        let res = check_if_admin(&config, &env.message.sender).unwrap_err();
        assert_eq!(res, StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));

        let env = mock_env("admin", &[], 600, 0);
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();

        let res = check_if_admin(&config, &env.message.sender);
        assert_eq!(res, Ok(()));

        let env = mock_env("triggerer", &[], 600, 0);
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let res = check_if_triggerer(&config, &env.message.sender);
        assert_eq!(res, Ok(()));

        let env = mock_env("non-triggerer", &[], 600, 0);
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let res = check_if_triggerer(&config, &env.message.sender).unwrap_err();
        assert_eq!(res, StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));

        //chnage admin
        let env = mock_env("not-admin", &[], 600, 0);
        let res = change_admin(&mut deps, env, HumanAddr("triggerer".to_string())).unwrap_err();
        assert_eq!(res, StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));

        let env = mock_env("admin", &[], 600, 0);
        let _res = change_admin(&mut deps, env, HumanAddr("someone".to_string())).unwrap();
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        assert_eq!(config.admin, HumanAddr("someone".to_string()));

        let env = mock_env("not-admin", &[], 600, 0);
        let res = change_admin(&mut deps, env, HumanAddr("triggerer".to_string())).unwrap_err();
        assert_eq!(res, StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));

        let env = mock_env("someone", &[], 600, 0);
        let _res = change_triggerer(&mut deps, env, HumanAddr("someone".to_string())).unwrap();
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();

        assert_eq!(config.triggerer, HumanAddr("someone".to_string()));
    }

    #[test]
    fn test_checking_contract_status() {
        //Contract balance > than
        let mut deps = deposit_helper_function(1000000000);

        let env = mock_env("admin", &[], 600, 0);

        let handle_msg = HandleMsg::SetStopAllStatus {};
        let _res = handle(&mut deps, env.clone(), handle_msg);

        let handle_msg = HandleMsg::TriggerWithdraw { amount: Uint128(500000000), padding: None };
        let res = handle(&mut deps, env.clone(), handle_msg);

        assert_eq!(res.unwrap_err(), StdError::generic_err(
            "This contract is stopped and this action is not allowed",
        ));

        let handle_msg = HandleMsg::SetStopAllButWithdrawStatus {};
        let _res = handle(&mut deps, env.clone(), handle_msg);

        let env = mock_env("Batman", &[], 600, 0);

        let handle_msg = HandleMsg::TriggerWithdraw { amount: Uint128(500000000), padding: None };
        let _res = handle(&mut deps, env, handle_msg);

        let env = mock_env("admin", &[], 600, 0);
        let handle_msg = HandleMsg::SetStopAllStatus {};
        let _res = handle(&mut deps, env.clone(), handle_msg);
    }

    #[test]
    fn testing_triggerer_rewards() {
        //Depositing amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 300));

        //Computing weights for the lottery

        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let mut configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let mut config: Config = configstore.load(CONFIG_KEY).unwrap();
        config.triggerer_share_percentage = 1;
        configstore.store(CONFIG_KEY, &config).unwrap();

        let handlemsg = HandleMsg::ChangeTriggererShare {
            percentage: 1,
            padding: None,
        };

        let _res = handle(&mut deps, mock_env("admin", &[], 10, 0), handlemsg);
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let _response = claim_rewards(&mut deps, mock_env("triggerer", &[], 10, config.unbonding_time)).unwrap();

        let user_prefixed = ReadonlyPrefixedStorage::multilevel(&[USER_INFO_KEY, "Batman".as_bytes()], &deps.storage);
        let user_store = TypedStore::<UserInfo, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&user_prefixed);
        let user =
            user_store.load("Batman".as_bytes())
                .unwrap_or(UserInfo { amount_delegated: Uint128(0), amount_available_for_withdraw: Uint128(0), requested_withdraw: vec![], total_won: Uint128(0), entry_index: vec![] }); // NotFound is the only possible error
        assert_eq!(user.requested_withdraw.len(), 0);
        assert_eq!(user.amount_delegated.0, 1000000000);
    }

    #[test]
    fn testing_triggerer_withdraw_rewards() {
        //Depositing amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 300));

        //Computing weights for the lottery
        let mut config_prefixed = PrefixedStorage::multilevel(&[CONFIG_KEY_PREFIX], &mut deps.storage);
        let configstore = TypedStoreMut::<Config, PrefixedStorage<'_, MockStorage>>::attach(&mut config_prefixed);
        let config: Config = configstore.load(CONFIG_KEY).unwrap();
        let _response = claim_rewards(&mut deps, mock_env("triggerer", &[], 10, config.unbonding_time,
        )).unwrap();
        let handlemsg = HandleMsg::TriggeringCostWithdraw {};
        let _res = handle(&mut deps, mock_env("triggerer", &[], 10, 0), handlemsg);

        let supply_pool_prefixed = ReadonlyPrefixedStorage::multilevel(&[SUPPLY_POOL_KEY_PREFIX], &deps.storage);
        let supply_store = TypedStore::<SupplyPool, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&supply_pool_prefixed);
        let supply_pool = supply_store.load(SUPPLY_POOL_KEY).unwrap();
        assert_eq!(supply_pool.triggerer_share, Uint128(0));
    }

    #[test]
    fn testing_change_lottery_duration() {
        //Depositing amount
        let (_init_result, mut deps) = init_helper(Some(800000000));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(600000000) }], 10, 0));
        let _ = try_deposit(&mut deps, mock_env("Batman", &[Coin { denom: "uscrt".to_string(), amount: Uint128(400000000) }], 10, 300));

        let handlemsg = HandleMsg::ChangeLotteryDuration { duration: 100 };
        let _res = handle(&mut deps, mock_env("admin", &[], 10, 0), handlemsg);

        let mut lottery_prefixed = ReadonlyPrefixedStorage::multilevel(&[LOTTERY_KEY_PREFIX], &deps.storage);
        let lottery_store = TypedStore::<Lottery, ReadonlyPrefixedStorage<'_, MockStorage>>::attach(&mut lottery_prefixed);
        let a_lottery = lottery_store.load(LOTTERY_KEY).unwrap();
        assert_eq!(a_lottery.duration, 100);
    }
}
