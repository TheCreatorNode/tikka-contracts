//! Prize claims, refunds, and authorization guards.

use super::*;

#[test]
fn non_winner_cannot_claim() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(&env);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let attacker = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let (token_addr, token_mint) = create_token(&env, &token_admin);
    token_mint.mint(&creator, &1_000_000);
    token_mint.mint(&buyer, &1_000_000);

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);

    let config = RaffleConfigBuilder::new(&env, token_addr.clone())
        .description(String::from_str(&env, "test raffle"))
        .end_time(2_000)
        .no_deadline(false)
        .max_tickets(2)
        .max_tickets_per_tx(2)
        .ticket_price(MIN_TICKET_PRICE)
        .prize_amount(MIN_TICKET_PRICE * 10)
        .claim_lockup_seconds(0)
        .build()
        .expect("valid claim config");

    client.init(&factory, &admin, &creator, &config);
    client.deposit_prize();
    client.buy_tickets(&buyer, &1);
    env.ledger().set_timestamp(2_000);
    client.finalize_raffle();

    let raffle = client.get_raffle();
    assert_eq!(raffle.winners.len(), 1);
    assert!(raffle.winners.get(0).unwrap().address != attacker);

    env.ledger()
        .set_timestamp(2_000 + DEFAULT_CLAIM_LOCKUP_SECONDS + 1);

    let start_events = env.events().all().len();
    let result = client.try_claim_prize(&attacker, &0u32);
    assert_eq!(env.events().all().len(), start_events);
    assert_eq!(result, Err(Ok(Error::NotWinner)));
}


#[test]
fn test_refund_guard_released_after_success() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(&env);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let payment_token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);

    let config = RaffleConfigBuilder::new(&env, payment_token.clone())
        .description(String::from_str(&env, "Test"))
        .end_time(10_000)
        .no_deadline(false)
        .max_tickets(1)
        .max_tickets_per_tx(1)
        .ticket_price(MIN_TICKET_PRICE)
        .prize_amount(MIN_TICKET_PRICE * 10)
        .build()
        .expect("valid refund guard config");

    client.init(&factory, &admin, &creator, &config);

    let start_events = env.events().all().len();
    let result = client.try_emergency_withdraw(&creator);
    assert_eq!(env.events().all().len(), start_events);
    assert_eq!(result.err(), Some(Ok(Error::PrizeNotDeposited)));
}


#[test]
fn test_claim_prize_deducts_protocol_fee() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(&env);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let treasury = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let payment_token = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let token_client = StellarAssetClient::new(&env, &payment_token);
    token_client.mint(&creator, &1_000_000);
    token_client.mint(&buyer, &1_000_000);

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);
    let config = RaffleConfigBuilder::new(&env, payment_token.clone())
        .description(String::from_str(&env, "Claim fee"))
        .max_tickets(1)
        .max_tickets_per_tx(1)
        .ticket_price(MIN_TICKET_PRICE)
        .prize_amount(MIN_TICKET_PRICE * 10)
        .protocol_fee_bp(1_000)
        .treasury_address(Some(treasury.clone()))
        .claim_lockup_seconds(0)
        .build()
        .expect("valid claim fee config");

    client.init(&factory, &admin, &creator, &config);
    client.deposit_prize();
    client.buy_tickets(&buyer, &1);
    client.finalize_raffle();

    let winner = client.get_raffle().winners.get(0).unwrap().address;
    let balance_before = token_client.balance(&winner);
    let gross = MIN_TICKET_PRICE * 10;
    let prize_fee = (gross * 1_000 + 9_999) / 10_000;
    let claimed = client.claim_prize(&winner, &0);

    assert_eq!(claimed, gross);
    assert_eq!(token_client.balance(&winner), balance_before + gross - prize_fee);
    assert_eq!(token_client.balance(&treasury), 1_000 + prize_fee);
}

#[test]
fn test_refund_ticket_credits_payer_not_owner() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(&env);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let (payment_token, token_client) = create_token(&env, &token_admin);
    token_client.mint(&creator, &1_000_000);
    token_client.mint(&payer, &1_000_000);

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);
    let config = RaffleConfigBuilder::new(&env, payment_token.clone())
        .description(String::from_str(&env, "Gift refund"))
        .end_time(10_000)
        .no_deadline(false)
        .max_tickets(2)
        .max_tickets_per_tx(2)
        .ticket_price(MIN_TICKET_PRICE)
        .prize_amount(MIN_TICKET_PRICE * 10)
        .build()
        .expect("valid gift refund config");

    client.init(&factory, &admin, &creator, &config);
    client.deposit_prize();

    // Gift purchase: `payer` funds the ticket, `recipient` owns it.
    client.buy_tickets_for(&payer, &recipient, &1);
    assert_eq!(
        client.get_my_tickets(&recipient),
        soroban_sdk::vec![&env, 0u32]
    );
    assert_eq!(client.get_my_tickets(&payer), soroban_sdk::Vec::new(&env));

    let payer_before = token_client.balance(&payer);
    let owner_before = token_client.balance(&recipient);

    client.cancel_raffle(&CancelReason::CreatorCancelled);
    let refunded = client.refund_ticket(&payer, &0);

    assert_eq!(refunded, MIN_TICKET_PRICE);
    assert_eq!(token_client.balance(&payer), payer_before + MIN_TICKET_PRICE);
    assert_eq!(token_client.balance(&recipient), owner_before);
}

#[test]
fn test_batch_refund_tickets_credits_payer_not_owner() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);

    let factory = Address::generate(&env);
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let payer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let (payment_token, token_client) = create_token(&env, &token_admin);
    token_client.mint(&creator, &1_000_000);
    token_client.mint(&payer, &1_000_000);

    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);
    let config = RaffleConfigBuilder::new(&env, payment_token.clone())
        .description(String::from_str(&env, "Gift batch refund"))
        .end_time(10_000)
        .no_deadline(false)
        .max_tickets(2)
        .max_tickets_per_tx(2)
        .ticket_price(MIN_TICKET_PRICE)
        .prize_amount(MIN_TICKET_PRICE * 10)
        .build()
        .expect("valid gift batch refund config");

    client.init(&factory, &admin, &creator, &config);
    client.deposit_prize();
    client.buy_tickets_for(&payer, &recipient, &2);

    let payer_before = token_client.balance(&payer);
    let owner_before = token_client.balance(&recipient);

    client.cancel_raffle(&CancelReason::CreatorCancelled);
    // The owner may drive the batch, but the refund still follows the payer.
    let refunded = client.batch_refund_tickets(&recipient, &soroban_sdk::vec![&env, 0u32, 1u32]);

    assert_eq!(refunded, MIN_TICKET_PRICE * 2);
    assert_eq!(
        token_client.balance(&payer),
        payer_before + MIN_TICKET_PRICE * 2
    );
    assert_eq!(token_client.balance(&recipient), owner_before);
}


