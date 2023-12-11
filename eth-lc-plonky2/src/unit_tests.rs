#[cfg(test)]
mod tests {
    use crate::merkle_tree_gadget::{
        add_verify_merkle_proof_target, set_verify_merkle_proof_target,
    };
    use crate::targets::{
        add_virtual_beacon_block_header_target, add_virtual_contract_state_target,
        add_virtual_find_sync_committee_target, add_virtual_signing_root_target,
        add_virtual_update_validity_target, add_virtual_verify_sync_committe_target,
        set_beacon_block_header_target, set_find_sync_committee_target, FINALIZED_HEADER_HEIGHT,
        FINALIZED_HEADER_INDEX, SYNC_COMMITTEE_HEIGHT,
    };
    use num::{BigUint, FromPrimitive};
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::{hash::WitnessHash, nonnative::gadgets::biguint::WitnessBigUint};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_signing_root() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let signing_root_target = add_virtual_signing_root_target(&mut builder);

        let attested_header_root = [
            45, 77, 212, 84, 150, 46, 105, 130, 179, 135, 133, 212, 122, 108, 73, 91, 45, 214, 160,
            140, 135, 132, 50, 138, 231, 168, 143, 75, 42, 25, 13, 56,
        ];

        let domain = [
            7, 0, 0, 0, 98, 137, 65, 239, 33, 209, 254, 140, 113, 52, 114, 10, 221, 16, 187, 145,
            227, 176, 44, 0, 126, 0, 70, 210, 71, 44, 102, 149,
        ];
        let signing_root = [
            114, 46, 13, 0, 130, 141, 69, 229, 6, 137, 227, 209, 63, 236, 236, 53, 67, 119, 8, 175,
            250, 218, 233, 60, 30, 139, 40, 113, 120, 169, 166, 22,
        ];

        let mut witness = PartialWitness::new();
        witness.set_hash256_target(&signing_root_target.header_root, &attested_header_root);
        witness.set_hash256_target(&signing_root_target.domain, &domain);
        witness.set_hash256_target(&signing_root_target.signing_root, &signing_root);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_beacon_block_header() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let beacon_block_header_target = add_virtual_beacon_block_header_target(&mut builder);

        let mut witness = PartialWitness::new();
        let header_root = [
            45, 77, 212, 84, 150, 46, 105, 130, 179, 135, 133, 212, 122, 108, 73, 91, 45, 214, 160,
            140, 135, 132, 50, 138, 231, 168, 143, 75, 42, 25, 13, 56,
        ];
        let parent_root = [
            83, 95, 167, 64, 47, 227, 70, 228, 57, 123, 161, 164, 51, 63, 52, 216, 95, 141, 127,
            21, 55, 239, 134, 108, 188, 248, 16, 182, 33, 81, 179, 144,
        ];
        let state_root = [
            34, 98, 151, 166, 168, 221, 147, 144, 81, 131, 90, 36, 198, 234, 171, 83, 62, 121, 54,
            203, 247, 208, 159, 81, 92, 252, 219, 26, 197, 148, 13, 153,
        ];
        let body_root = [
            141, 253, 157, 129, 148, 171, 105, 236, 221, 106, 218, 140, 98, 203, 197, 204, 199, 74,
            79, 14, 237, 91, 116, 9, 161, 189, 180, 200, 128, 82, 157, 194,
        ];
        let slot = 6588507;
        let proposer_index = 237719;
        set_beacon_block_header_target(
            &mut witness,
            &header_root,
            slot,
            proposer_index,
            &parent_root,
            &state_root,
            &body_root,
            &beacon_block_header_target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_verify_finality_branch() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let num_gates = builder.num_gates();

        let merkle_proof_target = add_verify_merkle_proof_target(
            &mut builder,
            FINALIZED_HEADER_INDEX,
            FINALIZED_HEADER_HEIGHT,
        );

        let finalized_header_root = [
            115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21,
            58, 28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
        ];
        let finality_branch = [
            [
                64, 36, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                233, 180, 31, 65, 72, 183, 68, 159, 102, 141, 82, 200, 172, 173, 178, 89, 14, 244,
                110, 47, 212, 112, 197, 34, 201, 99, 53, 72, 237, 186, 65, 172,
            ],
            [
                20, 10, 130, 54, 31, 190, 60, 68, 244, 247, 150, 180, 124, 159, 59, 56, 35, 124,
                131, 127, 234, 76, 23, 192, 214, 131, 24, 19, 33, 172, 113, 97,
            ],
            [
                213, 66, 0, 106, 64, 109, 139, 4, 121, 222, 140, 81, 115, 202, 61, 17, 66, 106,
                171, 221, 102, 167, 95, 122, 149, 254, 74, 190, 188, 26, 250, 60,
            ],
            [
                67, 107, 247, 11, 137, 44, 72, 207, 81, 150, 158, 192, 19, 211, 135, 177, 173, 6,
                202, 55, 216, 120, 224, 14, 26, 180, 146, 217, 90, 71, 52, 1,
            ],
            [
                46, 149, 59, 31, 38, 213, 233, 109, 245, 213, 4, 149, 212, 165, 43, 144, 210, 125,
                36, 216, 157, 233, 56, 249, 211, 137, 248, 242, 255, 220, 47, 7,
            ],
        ];
        let attested_state_root = [
            34, 98, 151, 166, 168, 221, 147, 144, 81, 131, 90, 36, 198, 234, 171, 83, 62, 121, 54,
            203, 247, 208, 159, 81, 92, 252, 219, 26, 197, 148, 13, 153,
        ];

        let mut witness = PartialWitness::new();
        set_verify_merkle_proof_target(
            &mut witness,
            &finalized_header_root,
            &finality_branch.to_vec(),
            &attested_state_root,
            &merkle_proof_target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_contract_state() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let contract_state_target = add_virtual_contract_state_target(&mut builder);

        let cur_slot: u64 = 6588416;
        let cur_header = [
            115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21,
            58, 28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
        ];
        let cur_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let cur_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];

        let new_slot: u64 = 6594720;
        let new_header = [
            181, 47, 90, 74, 144, 147, 36, 105, 62, 96, 18, 13, 201, 106, 185, 87, 99, 0, 172, 243,
            251, 239, 179, 67, 235, 186, 53, 70, 1, 99, 36, 59,
        ];

        let new_sync_committee_i = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_ii = [
            83, 234, 237, 227, 27, 56, 198, 90, 51, 53, 231, 79, 205, 86, 243, 22, 78, 64, 231, 34,
            181, 64, 117, 148, 168, 70, 125, 103, 132, 248, 196, 20,
        ];

        let cur_state = [
            150, 97, 120, 105, 126, 50, 222, 233, 169, 14, 3, 45, 102, 32, 221, 69, 151, 120, 157,
            18, 19, 66, 229, 81, 65, 253, 180, 52, 214, 21, 206, 131,
        ];
        let new_state = [
            138, 202, 109, 111, 105, 232, 211, 47, 153, 145, 225, 113, 61, 169, 147, 26, 82, 43,
            39, 187, 51, 189, 135, 92, 146, 108, 100, 39, 249, 104, 231, 198,
        ];

        let mut witness = PartialWitness::new();
        witness.set_hash256_target(&contract_state_target.cur_state, &cur_state);
        witness.set_hash256_target(&contract_state_target.cur_header, &cur_header);
        let mut cur_slot_bytes = [0u8; 32];
        cur_slot_bytes[0..8].copy_from_slice(&cur_slot.to_le_bytes());
        witness.set_hash256_target(&contract_state_target.cur_slot, &cur_slot_bytes);
        witness.set_hash256_target(
            &contract_state_target.cur_sync_committee_i,
            &cur_sync_committee_i,
        );
        witness.set_hash256_target(
            &contract_state_target.cur_sync_committee_ii,
            &cur_sync_committee_ii,
        );

        witness.set_hash256_target(&contract_state_target.new_state, &new_state);
        witness.set_hash256_target(&contract_state_target.new_header, &new_header);

        let mut new_slot_bytes = [0u8; 32];
        new_slot_bytes[0..8].copy_from_slice(&new_slot.to_le_bytes());
        witness.set_hash256_target(&contract_state_target.new_slot, &new_slot_bytes);
        witness.set_hash256_target(
            &contract_state_target.new_sync_committee_i,
            &new_sync_committee_i,
        );
        witness.set_hash256_target(
            &contract_state_target.new_sync_committee_ii,
            &new_sync_committee_ii,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_find_sync_committee_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let cur_slot = 6588416;
        let attested_slot1 = 6588417;
        let attested_slot2 = 6594800;
        let mut cur_sync_committee_i = [0u8; 32];
        cur_sync_committee_i[0] = 10;
        let mut cur_sync_committee_ii = [0u8; 32];
        cur_sync_committee_ii[20] = 70;

        let find_cur_sync_committee = add_virtual_find_sync_committee_target(&mut builder);
        let find_sync_committee_target2 = add_virtual_find_sync_committee_target(&mut builder);
        let mut witness = PartialWitness::new();

        set_find_sync_committee_target(
            &mut witness,
            attested_slot1,
            cur_slot,
            &cur_sync_committee_i,
            &cur_sync_committee_ii,
            &cur_sync_committee_i,
            find_cur_sync_committee,
        );
        set_find_sync_committee_target(
            &mut witness,
            attested_slot2,
            cur_slot,
            &cur_sync_committee_i,
            &cur_sync_committee_ii,
            &cur_sync_committee_ii,
            find_sync_committee_target2,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_verify_sync_committe_target_when_attested_from_next_period1() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let is_attested_from_next_period = true;
        let cur_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let cur_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_i = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_ii = [
            83, 234, 237, 227, 27, 56, 198, 90, 51, 53, 231, 79, 205, 86, 243, 22, 78, 64, 231, 34,
            181, 64, 117, 148, 168, 70, 125, 103, 132, 248, 196, 20,
        ];
        let finalized_state_root = [
            255, 194, 217, 140, 47, 98, 13, 224, 31, 61, 140, 226, 182, 49, 32, 135, 209, 115, 106,
            168, 199, 20, 150, 211, 204, 128, 11, 53, 4, 57, 189, 214,
        ];
        let new_sync_committee_ii_branch = [
            [
                91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120,
                98, 134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
            ],
            [
                192, 176, 252, 182, 85, 11, 154, 145, 221, 98, 155, 155, 158, 60, 173, 241, 213,
                54, 131, 211, 119, 194, 7, 157, 33, 187, 197, 222, 227, 216, 54, 98,
            ],
            [
                165, 36, 105, 106, 20, 36, 145, 228, 172, 136, 6, 141, 170, 197, 46, 200, 192, 152,
                92, 238, 87, 130, 126, 101, 160, 54, 142, 169, 71, 0, 39, 176,
            ],
            [
                4, 17, 122, 94, 130, 198, 53, 220, 161, 116, 98, 62, 225, 44, 232, 99, 6, 93, 128,
                0, 173, 254, 166, 231, 209, 149, 127, 31, 129, 251, 37, 168,
            ],
            [
                176, 81, 237, 96, 109, 253, 159, 172, 93, 93, 4, 53, 163, 64, 13, 153, 245, 72,
                150, 186, 226, 112, 59, 248, 20, 12, 219, 91, 31, 163, 108, 199,
            ],
        ];

        let verify_sync_committe_target = add_virtual_verify_sync_committe_target(&mut builder);
        witness.set_bool_target(
            verify_sync_committe_target.is_attested_from_next_period,
            is_attested_from_next_period,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_i,
            &cur_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_ii,
            &cur_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_i,
            &new_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_ii,
            &new_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.finalized_state_root,
            &finalized_state_root,
        );
        for (i, elm) in verify_sync_committe_target
            .new_sync_committee_ii_branch
            .iter()
            .enumerate()
        {
            witness.set_hash256_target(elm, &new_sync_committee_ii_branch[i]);
        }

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_verify_sync_committe_target_when_attested_from_next_period2() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let is_attested_from_next_period = true;
        let cur_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let cur_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let new_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let finalized_state_root = [
            255, 194, 217, 140, 47, 98, 13, 224, 31, 61, 140, 226, 182, 49, 32, 135, 209, 115, 106,
            168, 199, 20, 150, 211, 204, 128, 11, 53, 4, 57, 189, 214,
        ];
        let new_sync_committee_ii_branch = [
            [
                91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120,
                98, 134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
            ],
            [
                192, 176, 252, 182, 85, 11, 154, 145, 221, 98, 155, 155, 158, 60, 173, 241, 213,
                54, 131, 211, 119, 194, 7, 157, 33, 187, 197, 222, 227, 216, 54, 98,
            ],
            [
                165, 36, 105, 106, 20, 36, 145, 228, 172, 136, 6, 141, 170, 197, 46, 200, 192, 152,
                92, 238, 87, 130, 126, 101, 160, 54, 142, 169, 71, 0, 39, 176,
            ],
            [
                4, 17, 122, 94, 130, 198, 53, 220, 161, 116, 98, 62, 225, 44, 232, 99, 6, 93, 128,
                0, 173, 254, 166, 231, 209, 149, 127, 31, 129, 251, 37, 168,
            ],
            [
                176, 81, 237, 96, 109, 253, 159, 172, 93, 93, 4, 53, 163, 64, 13, 153, 245, 72,
                150, 186, 226, 112, 59, 248, 20, 12, 219, 91, 31, 163, 108, 199,
            ],
        ];

        let verify_sync_committe_target = add_virtual_verify_sync_committe_target(&mut builder);
        witness.set_bool_target(
            verify_sync_committe_target.is_attested_from_next_period,
            is_attested_from_next_period,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_i,
            &cur_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_ii,
            &cur_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_i,
            &new_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_ii,
            &new_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.finalized_state_root,
            &finalized_state_root,
        );
        for (i, elm) in verify_sync_committe_target
            .new_sync_committee_ii_branch
            .iter()
            .enumerate()
        {
            witness.set_hash256_target(elm, &new_sync_committee_ii_branch[i]);
        }

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_verify_sync_committe_target_when_not_attested_from_next_period1() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let is_attested_from_next_period = false;
        let cur_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let cur_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let new_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];

        let finalized_state_root = [
            143, 26, 135, 213, 152, 80, 148, 155, 254, 40, 98, 217, 181, 106, 140, 158, 97, 202,
            251, 182, 66, 88, 195, 40, 185, 115, 91, 206, 161, 169, 92, 68,
        ];
        let new_sync_committee_ii_branch = [
            [
                188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40,
                128, 239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
            ],
            [
                234, 231, 114, 54, 44, 243, 88, 150, 182, 242, 223, 157, 60, 29, 83, 156, 6, 39,
                101, 236, 42, 170, 102, 252, 57, 215, 255, 225, 79, 126, 26, 250,
            ],
            [
                145, 8, 55, 135, 154, 174, 40, 222, 108, 248, 187, 75, 236, 135, 131, 47, 234, 36,
                52, 180, 39, 168, 57, 216, 187, 36, 194, 17, 249, 249, 110, 227,
            ],
            [
                203, 62, 19, 218, 129, 48, 129, 182, 110, 184, 117, 219, 156, 120, 232, 225, 10,
                215, 55, 0, 132, 71, 29, 211, 67, 4, 5, 40, 149, 73, 80, 143,
            ],
            [
                7, 45, 207, 169, 60, 175, 233, 143, 99, 90, 153, 235, 109, 72, 14, 157, 242, 102,
                15, 129, 249, 250, 250, 77, 195, 143, 176, 208, 72, 180, 236, 202,
            ],
        ];

        let verify_sync_committe_target = add_virtual_verify_sync_committe_target(&mut builder);
        witness.set_bool_target(
            verify_sync_committe_target.is_attested_from_next_period,
            is_attested_from_next_period,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_i,
            &cur_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_ii,
            &cur_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_i,
            &new_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_ii,
            &new_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.finalized_state_root,
            &finalized_state_root,
        );
        for (i, elm) in verify_sync_committe_target
            .new_sync_committee_ii_branch
            .iter()
            .enumerate()
        {
            witness.set_hash256_target(elm, &new_sync_committee_ii_branch[i]);
        }

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_verify_sync_committe_target_when_not_attested_from_next_period2() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let is_attested_from_next_period = false;
        let cur_sync_committee_i = [
            188, 31, 36, 188, 220, 111, 116, 137, 15, 146, 183, 216, 229, 39, 129, 177, 40, 128,
            239, 35, 167, 206, 40, 212, 42, 230, 215, 31, 148, 161, 234, 95,
        ];
        let cur_sync_committee_ii = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_i = [
            91, 25, 250, 154, 30, 166, 30, 166, 57, 186, 237, 119, 150, 72, 21, 138, 84, 120, 98,
            134, 54, 209, 182, 48, 144, 79, 107, 143, 75, 69, 200, 78,
        ];
        let new_sync_committee_ii = [
            83, 234, 237, 227, 27, 56, 198, 90, 51, 53, 231, 79, 205, 86, 243, 22, 78, 64, 231, 34,
            181, 64, 117, 148, 168, 70, 125, 103, 132, 248, 196, 20,
        ];

        // can be any value like 0
        let finalized_state_root = [0; 32];
        // can be any value like 0
        let new_sync_committee_ii_branch = [[0; 32]; SYNC_COMMITTEE_HEIGHT];

        let verify_sync_committe_target = add_virtual_verify_sync_committe_target(&mut builder);
        witness.set_bool_target(
            verify_sync_committe_target.is_attested_from_next_period,
            is_attested_from_next_period,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_i,
            &cur_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.cur_sync_committee_ii,
            &cur_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_i,
            &new_sync_committee_i,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.new_sync_committee_ii,
            &new_sync_committee_ii,
        );
        witness.set_hash256_target(
            &verify_sync_committe_target.finalized_state_root,
            &finalized_state_root,
        );
        for (i, elm) in verify_sync_committe_target
            .new_sync_committee_ii_branch
            .iter()
            .enumerate()
        {
            witness.set_hash256_target(elm, &new_sync_committee_ii_branch[i]);
        }

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_update_validity() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let finalized_slot = 6594720;
        let cur_slot = finalized_slot - 1;
        let participation = 433;

        let update_validity_target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let cur_slot_big = BigUint::from_u64(cur_slot).unwrap();
        let finalized_slot_big = BigUint::from_u64(finalized_slot).unwrap();
        let participation_big = BigUint::from_u64(participation).unwrap();

        witness.set_biguint_target(&update_validity_target.cur_slot_big, &cur_slot_big);
        witness.set_biguint_target(
            &update_validity_target.finalized_slot_big,
            &finalized_slot_big,
        );
        witness.set_biguint_target(
            &update_validity_target.participation_big,
            &participation_big,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_panic_on_invalid_finalized_slot() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let finalized_slot = 6594720;
        let cur_slot = finalized_slot + 1;
        let participation = 433;

        let update_validity_target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let cur_slot_big = BigUint::from_u64(cur_slot).unwrap();
        let finalized_slot_big = BigUint::from_u64(finalized_slot).unwrap();
        let participation_big = BigUint::from_u64(participation).unwrap();

        witness.set_biguint_target(&update_validity_target.cur_slot_big, &cur_slot_big);
        witness.set_biguint_target(
            &update_validity_target.finalized_slot_big,
            &finalized_slot_big,
        );
        witness.set_biguint_target(
            &update_validity_target.participation_big,
            &participation_big,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_panic_on_invalid_participation() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let finalized_slot = 6594720;
        let cur_slot = finalized_slot - 1;
        let participation = 300;

        let update_validity_target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let cur_slot_big = BigUint::from_u64(cur_slot).unwrap();
        let finalized_slot_big = BigUint::from_u64(finalized_slot).unwrap();
        let participation_big = BigUint::from_u64(participation).unwrap();

        witness.set_biguint_target(&update_validity_target.cur_slot_big, &cur_slot_big);
        witness.set_biguint_target(
            &update_validity_target.finalized_slot_big,
            &finalized_slot_big,
        );
        witness.set_biguint_target(
            &update_validity_target.participation_big,
            &participation_big,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
