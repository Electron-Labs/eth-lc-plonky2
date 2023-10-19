use eth_lc_plonky2::eth_ssz_containers::{
    add_virtual_proof_target, register_hash256_public_inputs, set_proof_target,
};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let attested_header_root = [
        45, 77, 212, 84, 150, 46, 105, 130, 179, 135, 133, 212, 122, 108, 73, 91, 45, 214, 160,
        140, 135, 132, 50, 138, 231, 168, 143, 75, 42, 25, 13, 56,
    ];
    let domain = [
        7, 0, 0, 0, 98, 137, 65, 239, 33, 209, 254, 140, 113, 52, 114, 10, 221, 16, 187, 145, 227,
        176, 44, 0, 126, 0, 70, 210, 71, 44, 102, 149,
    ];
    let signing_root = [
        114, 46, 13, 0, 130, 141, 69, 229, 6, 137, 227, 209, 63, 236, 236, 53, 67, 119, 8, 175,
        250, 218, 233, 60, 30, 139, 40, 113, 120, 169, 166, 22,
    ];
    let attested_parent_root = [
        83, 95, 167, 64, 47, 227, 70, 228, 57, 123, 161, 164, 51, 63, 52, 216, 95, 141, 127, 21,
        55, 239, 134, 108, 188, 248, 16, 182, 33, 81, 179, 144,
    ];
    let attested_state_root = [
        34, 98, 151, 166, 168, 221, 147, 144, 81, 131, 90, 36, 198, 234, 171, 83, 62, 121, 54, 203,
        247, 208, 159, 81, 92, 252, 219, 26, 197, 148, 13, 153,
    ];
    let attested_body_root = [
        141, 253, 157, 129, 148, 171, 105, 236, 221, 106, 218, 140, 98, 203, 197, 204, 199, 74, 79,
        14, 237, 91, 116, 9, 161, 189, 180, 200, 128, 82, 157, 194,
    ];
    let attested_slot = 6588507;
    let attested_proposer_index = 237719;
    let finalized_header_root = [
        115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21, 58,
        28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
    ];
    let finality_branch = [
        [
            64, 36, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ],
        [
            233, 180, 31, 65, 72, 183, 68, 159, 102, 141, 82, 200, 172, 173, 178, 89, 14, 244, 110,
            47, 212, 112, 197, 34, 201, 99, 53, 72, 237, 186, 65, 172,
        ],
        [
            20, 10, 130, 54, 31, 190, 60, 68, 244, 247, 150, 180, 124, 159, 59, 56, 35, 124, 131,
            127, 234, 76, 23, 192, 214, 131, 24, 19, 33, 172, 113, 97,
        ],
        [
            213, 66, 0, 106, 64, 109, 139, 4, 121, 222, 140, 81, 115, 202, 61, 17, 66, 106, 171,
            221, 102, 167, 95, 122, 149, 254, 74, 190, 188, 26, 250, 60,
        ],
        [
            67, 107, 247, 11, 137, 44, 72, 207, 81, 150, 158, 192, 19, 211, 135, 177, 173, 6, 202,
            55, 216, 120, 224, 14, 26, 180, 146, 217, 90, 71, 52, 1,
        ],
        [
            46, 149, 59, 31, 38, 213, 233, 109, 245, 213, 4, 149, 212, 165, 43, 144, 210, 125, 36,
            216, 157, 233, 56, 249, 211, 137, 248, 242, 255, 220, 47, 7,
        ],
    ];

    let finalized_slot = 6588416;
    let finalized_proposer_index = 204412;
    let finalized_parent_root = [
        75, 11, 236, 33, 77, 71, 246, 182, 71, 187, 162, 159, 143, 53, 200, 219, 19, 236, 186, 158,
        251, 156, 67, 75, 223, 45, 127, 6, 117, 15, 14, 130,
    ];
    let finalized_state_root = [
        143, 26, 135, 213, 152, 80, 148, 155, 254, 40, 98, 217, 181, 106, 140, 158, 97, 202, 251,
        182, 66, 88, 195, 40, 185, 115, 91, 206, 161, 169, 92, 68,
    ];
    let finalized_body_root = [
        95, 163, 11, 145, 230, 175, 96, 188, 113, 93, 206, 8, 55, 80, 189, 8, 2, 164, 101, 96, 123,
        64, 86, 208, 245, 151, 95, 215, 157, 65, 148, 16,
    ];

    let contract_head = finalized_slot - 1; // contract state
    let mut current_period_sync_committee_poseidon = [0u8; 32]; // contract state
    current_period_sync_committee_poseidon[0] = 10;
    let participation = 350;

    let target = add_virtual_proof_target(&mut builder);

    // register public inputs
    // register_hash256_public_inputs(
    //     &mut builder,
    //     &vec![
    //         target.signing_root,
    //         target.attested_header_root,
    //         target.domain,
    //         target.attested_slot,
    //         target.attested_proposer_index,
    //         target.attested_parent_root,
    //         target.attested_state_root,
    //         target.attested_body_root,
    //         target.finalized_header_root,
    //         target.finalized_slot_h256,
    //         target.finalized_proposer_index,
    //         target.finalized_parent_root,
    //         target.finalized_state_root,
    //         target.finalized_body_root,
    //         target.current_period_sync_committee_poseidon
    //     ],
    // );
    // register_hash256_public_inputs(&mut builder, &target.finality_branch);

    let mut pw = PartialWitness::new();
    set_proof_target(
        &mut pw,
        &signing_root,
        &attested_header_root,
        &domain,
        attested_slot,
        attested_proposer_index,
        &attested_parent_root,
        &attested_state_root,
        &attested_body_root,
        &finalized_header_root,
        &finality_branch,
        finalized_slot,
        finalized_proposer_index,
        &finalized_parent_root,
        &finalized_state_root,
        &finalized_body_root,
        contract_head,
        &current_period_sync_committee_poseidon,
        participation,
        &target,
    );

    let data = builder.build::<C>();
    let start_time = std::time::Instant::now();
    let proof = data.prove(pw).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    assert!(data.verify(proof).is_ok());
}
