use eth_lc_plonky2::targets::{
    add_virtual_proof_target, register_hash256_public_inputs, set_proof_target,
};
use num::{BigUint, FromPrimitive};
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
        45, 46, 11, 136, 235, 78, 3, 151, 19, 228, 16, 48, 115, 245, 106, 188, 84, 93, 97, 161,
        234, 102, 5, 70, 123, 252, 35, 196, 121, 101, 208, 169,
    ];
    let domain = [
        7, 0, 0, 0, 98, 137, 65, 239, 33, 209, 254, 140, 113, 52, 114, 10, 221, 16, 187, 145, 227,
        176, 44, 0, 126, 0, 70, 210, 71, 44, 102, 149,
    ];
    let signing_root = [
        56, 34, 152, 174, 255, 250, 16, 209, 187, 193, 153, 135, 200, 211, 31, 48, 199, 67, 135, 8,
        13, 126, 185, 128, 199, 225, 26, 36, 76, 29, 30, 24,
    ];
    let attested_parent_root = [
        213, 76, 68, 219, 231, 47, 225, 89, 64, 174, 35, 97, 236, 85, 92, 30, 69, 195, 16, 211, 39,
        116, 204, 209, 115, 104, 174, 98, 2, 139, 174, 188,
    ];
    let attested_state_root = [
        63, 9, 75, 128, 166, 145, 188, 227, 140, 72, 0, 97, 242, 221, 96, 205, 96, 4, 87, 142, 166,
        173, 235, 32, 25, 129, 185, 198, 51, 19, 222, 37,
    ];
    let attested_body_root = [
        47, 103, 87, 100, 235, 133, 223, 8, 241, 35, 41, 215, 182, 47, 244, 214, 153, 23, 154, 152,
        34, 90, 84, 243, 247, 10, 86, 61, 40, 217, 22, 179,
    ];
    let attested_slot = 6594800;
    let attested_proposer_index = 129338;
    let finalized_header_root = [
        181, 47, 90, 74, 144, 147, 36, 105, 62, 96, 18, 13, 201, 106, 185, 87, 99, 0, 172, 243,
        251, 239, 179, 67, 235, 186, 53, 70, 1, 99, 36, 59,
    ];
    let finality_branch = [
        [
            5, 37, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            94, 55, 201, 67, 169, 114, 49, 101, 76, 59, 176, 39, 192, 166, 77, 126, 236, 211, 158,
            22, 111, 58, 108, 110, 54, 147, 11, 36, 168, 93, 204, 220,
        ],
        [
            8, 243, 135, 44, 165, 69, 219, 40, 142, 167, 91, 236, 16, 141, 72, 178, 46, 254, 254,
            222, 44, 195, 253, 46, 150, 235, 43, 97, 56, 219, 200, 211,
        ],
        [
            32, 187, 215, 199, 83, 3, 35, 106, 19, 235, 176, 126, 125, 224, 39, 82, 198, 63, 23,
            201, 142, 233, 64, 218, 46, 15, 120, 3, 240, 53, 245, 70,
        ],
        [
            74, 134, 157, 134, 15, 2, 90, 127, 92, 87, 114, 210, 19, 176, 7, 231, 124, 35, 24, 182,
            150, 206, 137, 194, 18, 18, 109, 43, 167, 165, 188, 233,
        ],
        [
            232, 122, 159, 132, 245, 105, 223, 74, 123, 6, 67, 140, 167, 85, 144, 113, 116, 158,
            82, 174, 184, 248, 74, 214, 236, 65, 164, 36, 144, 53, 1, 81,
        ],
    ];

    let finalized_slot = 6594720;
    let finalized_proposer_index = 568529;
    let finalized_parent_root = [
        180, 103, 151, 22, 8, 23, 130, 247, 9, 74, 38, 255, 22, 181, 149, 170, 41, 158, 249, 110,
        167, 43, 29, 101, 138, 254, 184, 160, 83, 107, 44, 205,
    ];
    let finalized_state_root = [
        255, 194, 217, 140, 47, 98, 13, 224, 31, 61, 140, 226, 182, 49, 32, 135, 209, 115, 106,
        168, 199, 20, 150, 211, 204, 128, 11, 53, 4, 57, 189, 214,
    ];
    let finalized_body_root = [
        27, 8, 73, 47, 97, 144, 162, 131, 173, 140, 159, 231, 192, 84, 246, 121, 7, 105, 106, 35,
        196, 60, 171, 172, 154, 28, 11, 196, 32, 10, 148, 81,
    ];

    let curr_contract_header = [
        115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21, 58,
        28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
    ];
    let curr_contract_slot = 6588416;

    let mut curr_sync_committee_i = [0u8; 32];
    curr_sync_committee_i[0] = 10;
    let mut curr_sync_committee_ii = [0u8; 32];
    curr_sync_committee_ii[20] = 70;
    let participation = 350;

    let mut new_sync_committee_i = [0u8; 32];
    new_sync_committee_i[0] = 10;
    let mut new_sync_committee_ii = [0u8; 32];
    new_sync_committee_ii[20] = 70;

    let curr_contract_state = [
        184, 125, 255, 223, 248, 134, 92, 238, 197, 185, 188, 16, 90, 177, 15, 38, 36, 56, 168,
        111, 27, 58, 138, 200, 137, 14, 185, 195, 135, 70, 115, 55,
    ];
    let new_contract_state = [
        248, 94, 17, 117, 76, 129, 51, 3, 205, 253, 251, 77, 214, 130, 186, 45, 159, 36, 3, 207,
        18, 28, 69, 31, 108, 98, 31, 64, 45, 121, 43, 142,
    ];

    let target = add_virtual_proof_target(&mut builder);

    // let a = BigUint::from_u64(finalized_slot).unwrap();
    // println!("a {:?}", a.lim);

    // register public inputs
    // participation?
    // TODO: connect finalized_slot in validity and in beacon block header: one is biguint, other is Hash256
    // register_hash256_public_inputs(
    //     &mut builder,
    //     &vec![
    //         target.curr_contract_slot,
    //         target.current_sync_committee_poseidon,
    //         target.finalized_header_root,
    //         target.finalized_slot_h256,
    //         target.finalized_beacon_block_header_target.slot,
    //     ],
    // );

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
        &curr_contract_state,
        &new_contract_state,
        &curr_contract_header,
        curr_contract_slot,
        &curr_sync_committee_i,
        &curr_sync_committee_ii,
        &new_sync_committee_i,
        &new_sync_committee_ii,
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
