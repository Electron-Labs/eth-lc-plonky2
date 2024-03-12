use eth_lc_plonky2::{
    targets::{add_virtual_proof_target, set_proof_target}, 
    utils::{ compute_signing_root, get_attested_header_from_light_client_update_json_str, get_finality_update_from_light_client_update_json_str, get_sync_aggregate_from_light_client_update_json_str, get_sync_committee_update_from_light_client_update_json_str, BeaconRPCRoutes, BeaconRPCVersion}};
use eth_types::H256;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs,
    },
};
use plonky2_circuit_serializer::serializer::CustomGateSerializer;
use tree_hash::TreeHash;
use std::io::Read;
use std::fs::File;

#[derive(Debug, Clone, tree_hash_derive::TreeHash)]
pub struct ContractState {
    cur_slot: u64,
    cur_header: [u8; 32],
    cur_sync_committee_i: [u8; 32],
    cur_sync_committee_ii: [u8; 32],
}

// TODO: use sync committee proof from lc update
fn main() {
    env_logger::init();

    let mut file = File::open("eth-lc-plonky2/src/light_client_update_period_634.json").unwrap();
    let mut light_client_update_json_str = String::new();
    file.read_to_string(&mut light_client_update_json_str)
        .expect("Unable to read file");

    let mut prev_file = File::open("eth-lc-plonky2/src/light_client_update_period_633.json").unwrap();
    let mut prev_light_client_update_json_str = String::new();
    prev_file.read_to_string(&mut prev_light_client_update_json_str)
        .expect("Unable to read file");

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

    let domain:[u8;32] = hex::decode("0x07000000628941ef21d1fe8c7134720add10bb91e3b02c007e0046d2472c6695".split_at(2).1).unwrap().try_into().unwrap();
    
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

    let sync_committee_update = get_sync_committee_update_from_light_client_update_json_str(&routes, &light_client_update_json_str).unwrap();
    let prev_sync_committee_update = get_sync_committee_update_from_light_client_update_json_str(&routes,&prev_light_client_update_json_str).unwrap();

    let cur_slot = 5188736;
    let cur_header = hex::decode("0xfe2c5e5a3f845dc9af5b872f05d92730ea7017ac0048c0f5598345b019e42667".split_at(2).1).unwrap().try_into().unwrap();
    //TODO: Fetch this data from RPC From current and prev sync committee
    let cur_sync_committee_i = hex::decode("0xd6e98c7049b61922896ec35eed5e2c35c1512899dd882d81e431b8a6e2e4bb2d".split_at(2).1).unwrap().try_into().unwrap();
    let cur_sync_committee_ii = hex::decode("0x8727843ae07df817392eba322811aa49019ddeccf5257929a4a3b32a3a44e5be".split_at(2).1).unwrap().try_into().unwrap();

    let cur_state = ContractState {
        cur_slot,
        cur_header,
        cur_sync_committee_i,
        cur_sync_committee_ii,
    };
    let cur_state = cur_state.tree_hash_root().0;

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

    let sync_committee_aggregate = prev_sync_committee_update.next_sync_committee.aggregate_pubkey.0.to_vec();

    let sync_aggregate = get_sync_aggregate_from_light_client_update_json_str(&light_client_update_json_str).unwrap();
    let mut sync_committee_bits= Vec::new();
    for num in sync_aggregate.sync_committee_bits.0 {
        for j in 0..8{
            sync_committee_bits.push((num>>j & 1) == 1);
        }
    }
    let signature = sync_aggregate.sync_committee_signature.0.to_vec();

    let proof_bytes = std::fs::read("../starky_bls12_381/proof_with_pis.bin").unwrap();
    let verifier_bytes = std::fs::read("../starky_bls12_381/verifier_only.bin").unwrap();
    let cd_bytes = std::fs::read("../starky_bls12_381/common_data.bin").unwrap();

    let common_data = CommonCircuitData::from_bytes(cd_bytes, &CustomGateSerializer).unwrap();
    let bls_proof = ProofWithPublicInputs::from_bytes(proof_bytes, &common_data).unwrap();
    let bls_verifier_data = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_bytes).unwrap();
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
