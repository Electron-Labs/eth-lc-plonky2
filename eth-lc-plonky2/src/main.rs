use eth_lc_plonky2::{
    targets::{add_virtual_proof_target, set_proof_target}, 
    utils::{ compute_signing_root, get_attested_header_from_light_client_update_json_str, get_finality_update_from_light_client_update_json_str, get_sync_aggregate_from_light_client_update_json_str, get_sync_committee_update_from_light_client_update_json_str, BeaconRPCRoutes, BeaconRPCVersion}};
use eth_types::H256;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use tree_hash::TreeHash;
use std::fs::File;
use reqwest;
use serde_yaml;
use eth2_utility::consensus::{Network, NetworkConfig,compute_domain,DOMAIN_SYNC_COMMITTEE};
use starky_bls12_381::aggregate_proof::aggregate_proof;


#[derive(Debug, Clone, tree_hash_derive::TreeHash)]
pub struct ContractState {
    cur_slot: u64,
    cur_header: [u8; 32],
    cur_sync_committee_i: [u8; 32],
    cur_sync_committee_ii: [u8; 32],
}

// TODO: use sync committee proof from lc update
#[tokio::main]
async fn main() {
    env_logger::init();

    let yaml_file = File::open("eth-lc-plonky2/src/rpc.yaml").unwrap();
    let yaml_data: serde_yaml::Value = serde_yaml::from_reader(yaml_file).expect("not able to read yaml");

    let finality_update_rpc = yaml_data["finality_update_rpc"].as_str().unwrap();
    let light_client_rpc = yaml_data["light_client_rpc"].as_str().unwrap();

    let latest_finality_update: serde_json::Value = reqwest::get(finality_update_rpc)
                                                    .await
                                                    .unwrap()
                                                    .json()
                                                    .await
                                                    .unwrap();
    let latest_slot = latest_finality_update["data"]["attested_header"]["beacon"]["slot"].as_str().unwrap().parse::<u64>().unwrap();
    let period = latest_slot/(256 * 32);
    let prev_period = period - 1;

    let url = format!("{}?start_period={}&count={}",light_client_rpc, prev_period, 2);
    let combined_period_lc_updates: serde_json::Value = reqwest::get(url)
                                                        .await
                                                        .unwrap()
                                                        .json()
                                                        .await
                                                        .unwrap();


    let prev_light_client_update_json = combined_period_lc_updates[0].clone();
    let prev_light_client_update_json_str = combined_period_lc_updates[0].to_string();     
    let light_client_update_json_str = combined_period_lc_updates[1].to_string();   

    let routes = BeaconRPCRoutes{
        get_block: String::from(""),
        get_block_header: String::from(""),
        get_light_client_finality_update: String::from(""),
        get_light_client_update: String::from(""),
        get_light_client_update_by_epoch: String::from(""),
        get_bootstrap: String::from(""),
        get_state: String::from(""),
        version: BeaconRPCVersion::V1_5,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let eth_network = Network::Mainnet;
    let eth_network_config = NetworkConfig::new(&eth_network);

    let domain:[u8;32] = compute_domain(DOMAIN_SYNC_COMMITTEE, eth_network_config.deneb_fork_version, H256::from(eth_network_config.genesis_validators_root)).0.0;
    
    let attested_header = get_attested_header_from_light_client_update_json_str(&routes, &light_client_update_json_str).unwrap();
    let domain_h256 = H256::from(domain);
    let signing_root = compute_signing_root(eth_types::H256(attested_header.tree_hash_root()), domain_h256).0.0;

    let attested_slot = attested_header.slot;
    let attested_proposer_index = attested_header.proposer_index;
    let attested_header_root = attested_header.tree_hash_root().0;
    let attested_parent_root = attested_header.parent_root.0.0;
    let attested_state_root = attested_header.state_root.0.0;
    let attested_body_root = attested_header.body_root.0.0;

    let finalized_header_update = get_finality_update_from_light_client_update_json_str(&routes, &light_client_update_json_str).unwrap();
    let finalized_slot = finalized_header_update.header_update.beacon_header.slot;
    let finalized_proposer_index = finalized_header_update.header_update.beacon_header.proposer_index;
    let finalized_header_root = finalized_header_update.header_update.beacon_header.tree_hash_root().0;
    let finalized_parent_root = finalized_header_update.header_update.beacon_header.parent_root.0.0;
    let finalized_state_root = finalized_header_update.header_update.beacon_header.state_root.0.0;
    let finalized_body_root = finalized_header_update.header_update.beacon_header.body_root.0.0;
    let finality_branch = finalized_header_update.finality_branch
                                                                .iter()
                                                                .map(|i| i.0.0)
                                                                .collect::<Vec<[u8;32]>>()
                                                                .try_into()
                                                                .expect("Incorrect Length");
    // let cur_state = [
    //     150, 97, 120, 105, 126, 50, 222, 233, 169, 14, 3, 45, 102, 32, 221, 69, 151, 120, 157, 18,
    //     19, 66, 229, 81, 65, 253, 180, 52, 214, 21, 206, 131,
    // ];
    // let new_state = [
    //     138, 202, 109, 111, 105, 232, 211, 47, 153, 145, 225, 113, 61, 169, 147, 26, 82, 43, 39,
    //     187, 51, 189, 135, 92, 146, 108, 100, 39, 249, 104, 231, 198,
    // ];


    let prev_finalized_header_update = get_finality_update_from_light_client_update_json_str(&routes, &prev_light_client_update_json_str).unwrap();
    let cur_slot = prev_finalized_header_update.header_update.beacon_header.slot;
    let cur_header = prev_finalized_header_update.header_update.beacon_header.tree_hash_root().0;
    //TODO: Fetch this data from RPC From current and prev sync committee
    let prev_sync_committee_update = get_sync_committee_update_from_light_client_update_json_str(&routes,&prev_light_client_update_json_str).unwrap();
    let cur_sync_committee_i = prev_sync_committee_update.next_sync_committee_branch[0].0.0;
    let cur_sync_committee_ii = prev_sync_committee_update.next_sync_committee.tree_hash_root().0;

    let cur_state = ContractState {
        cur_slot,
        cur_header,
        cur_sync_committee_i,
        cur_sync_committee_ii,
    };
    let cur_state = cur_state.tree_hash_root().0;

    let sync_committee_update = get_sync_committee_update_from_light_client_update_json_str(&routes, &light_client_update_json_str).unwrap();
    //TODO: Fetch this data from RPC From current and prev sync committee
    let new_sync_committee_i = sync_committee_update.next_sync_committee_branch[0].0.0;
    let new_sync_committee_ii = sync_committee_update.next_sync_committee.tree_hash_root().0;

    let new_state = ContractState {
        cur_slot: finalized_slot,
        cur_header: finalized_header_root,
        cur_sync_committee_i: new_sync_committee_i,
        cur_sync_committee_ii: new_sync_committee_ii,
    };
    let new_state = new_state.tree_hash_root().0;
    // let participation = 433;
    let new_sync_committee_ii_branch:[[u8;32];5] = sync_committee_update.next_sync_committee_branch.iter().map(|i| i.0.0).collect::<Vec<[u8;32]>>().try_into().expect("Incorrect length");
    let sync_committee_pubkeys = prev_sync_committee_update.next_sync_committee.pubkeys.0
                                                                                                        .iter()
                                                                                                        .map(|i| i.0.to_vec())
                                                                                                        .collect::<Vec<Vec<u8>>>();

    let sync_committe_pubkeys_str = prev_light_client_update_json["data"]["next_sync_committee"]["pubkeys"]
                                                                                                                .as_array().unwrap()
                                                                                                                .iter()
                                                                                                                .map(|i| i.to_string())
                                                                                                                .collect::<Vec<String>>();

    let sync_committee_aggregate = prev_sync_committee_update.next_sync_committee.aggregate_pubkey.0.to_vec();

    let sync_aggregate = get_sync_aggregate_from_light_client_update_json_str(&light_client_update_json_str).unwrap();
    let mut sync_committee_bits= Vec::new();
    for num in sync_aggregate.sync_committee_bits.0 {
        for j in 0..8{
            sync_committee_bits.push((num>>j & 1) == 1);
        }
    }
    let signature = sync_aggregate.sync_committee_signature.0.to_vec();

    let proof = aggregate_proof(sync_committe_pubkeys_str, sync_aggregate, signing_root, prev_sync_committee_update);
    
    let common_data = proof.2;
    let bls_proof = proof.0;
    let bls_verifier_data = proof.1;
    let target = add_virtual_proof_target::<F, D, C>(&mut builder, &common_data);

    // register public inputs
    target
        .cur_state
        .iter()
        .for_each(|elm| builder.register_public_input(elm.0));
    target
        .new_state
        .iter()
        .for_each(|elm| builder.register_public_input(elm.0));

    let mut witness = PartialWitness::new();
    set_proof_target(
        &mut witness,
        &signing_root,
        &domain,
        attested_slot,
        attested_proposer_index,
        &attested_header_root,
        &attested_parent_root,
        &attested_state_root,
        &attested_body_root,
        finalized_slot,
        finalized_proposer_index,
        &finalized_header_root,
        &finalized_parent_root,
        &finalized_state_root,
        &finalized_body_root,
        &finality_branch,
        &cur_state,
        &new_state,
        cur_slot,
        &cur_header,
        &cur_sync_committee_i,
        &cur_sync_committee_ii,
        &new_sync_committee_i,
        &new_sync_committee_ii,
        &sync_committee_bits,
        // participation,
        &new_sync_committee_ii_branch,
        &sync_committee_pubkeys,
        &sync_committee_aggregate,
        &signature,
        &bls_proof,
        &bls_verifier_data,
        &target,
    );

    builder.print_gate_counts(0);
    let data = builder.build::<C>();
    println!("degree - {}", data.common.fri_params.degree_bits);
    let start_time = std::time::Instant::now();
    let proof = data.prove(witness).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    assert!(data.verify(proof).is_ok());
}
