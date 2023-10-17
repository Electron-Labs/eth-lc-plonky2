use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    hash::{sha256::WitnessHashSha2, CircuitBuilderHash, Hash256Target, WitnessHash},
    u32::arithmetic_u32::CircuitBuilderU32,
};

use crate::merkle_tree_gadget::{
    add_virtual_merkle_tree_sha256_target, set_verify_merkle_proof_target, VerifyMerkleProofTarget,
};

pub struct BeaconBlockHeaderTarget {
    pub header_root: Hash256Target,
    pub slot: Hash256Target,
    pub proposer_index: Hash256Target,
    pub parent_root: Hash256Target,
    pub state_root: Hash256Target,
    pub body_root: Hash256Target,
}

pub struct SigningRootTarget {
    pub signing_root: Hash256Target,
    pub header_root: Hash256Target,
    pub domain: Hash256Target,
}

pub fn add_virtual_beacon_block_header_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BeaconBlockHeaderTarget {
    let slot = builder.add_virtual_hash256_target();
    let proposer_index = builder.add_virtual_hash256_target();
    let parent_root = builder.add_virtual_hash256_target();
    let state_root = builder.add_virtual_hash256_target();
    let body_root = builder.add_virtual_hash256_target();
    let header_root = builder.add_virtual_hash256_target();

    let merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 3);
    builder.connect_hash256(slot, merkle_tree_target.leaves[0]);
    builder.connect_hash256(proposer_index, merkle_tree_target.leaves[1]);
    builder.connect_hash256(parent_root, merkle_tree_target.leaves[2]);
    builder.connect_hash256(state_root, merkle_tree_target.leaves[3]);
    builder.connect_hash256(body_root, merkle_tree_target.leaves[4]);

    let zero_u32 = builder.zero_u32();
    for &target in merkle_tree_target.leaves[5..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    builder.connect_hash256(header_root, merkle_tree_target.root);
    BeaconBlockHeaderTarget {
        header_root,
        slot,
        proposer_index,
        parent_root,
        state_root,
        body_root,
    }
}

pub fn add_virtual_signing_root_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> SigningRootTarget {
    let header_root = builder.add_virtual_hash256_target();
    let domain = builder.add_virtual_hash256_target();
    let signing_root = builder.add_virtual_hash256_target();

    let merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 1);
    builder.connect_hash256(header_root, merkle_tree_target.leaves[0]);
    builder.connect_hash256(domain, merkle_tree_target.leaves[1]);

    let zero_u32 = builder.zero_u32();
    for &target in merkle_tree_target.leaves[2..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    builder.connect_hash256(signing_root, merkle_tree_target.root);

    SigningRootTarget {
        signing_root,
        header_root,
        domain,
    }
}

pub fn set_beacon_block_header_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    header_root: &[u8; 32],
    slot: u64,
    proposer_index: u64,
    parent_root: &[u8; 32],
    state_root: &[u8; 32],
    body_root: &[u8; 32],
    target: &BeaconBlockHeaderTarget,
) {
    witness.set_hash256_target(&target.header_root, header_root);
    witness.set_hash256_target(&target.parent_root, parent_root);
    witness.set_hash256_target(&target.state_root, state_root);
    witness.set_hash256_target(&target.body_root, body_root);

    let mut slot_bytes = [0u8; 32];
    slot_bytes[0..8].copy_from_slice(&slot.to_le_bytes());
    witness.set_hash256_target(&target.slot, &slot_bytes);

    let mut proposer_index_bytes = [0u8; 32];
    proposer_index_bytes[0..8].copy_from_slice(&proposer_index.to_le_bytes());
    witness.set_hash256_target(&target.proposer_index, &proposer_index_bytes);
}

pub fn set_signing_root_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    header_root: &[u8; 32],
    domain: &[u8; 32],
    signing_root: &[u8; 32],
    target: &SigningRootTarget,
) {
    witness.set_hash256_target(&target.header_root, header_root);
    witness.set_hash256_target(&target.domain, domain);
    witness.set_hash256_target(&target.signing_root, signing_root);
}

pub fn set_virtual_finality_branch_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    finalized_header_root: &[u8; 32],
    proof: &[[u8; 32]; 6],
    attested_state_root: &[u8; 32],
    target: &VerifyMerkleProofTarget,
) {
    set_verify_merkle_proof_target(
        witness,
        finalized_header_root,
        &proof.to_vec(),
        attested_state_root,
        target,
    );
}

#[cfg(test)]
mod tests {
    use crate::eth_ssz_containers::{
        add_virtual_beacon_block_header_target, add_virtual_signing_root_target,
        set_beacon_block_header_target, set_signing_root_target,
        set_virtual_finality_branch_target,
    };
    use crate::merkle_tree_gadget::add_verify_merkle_proof_target;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    #[test]
    fn test_beacon_block_header() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let beacon_block_header_target = add_virtual_beacon_block_header_target(&mut builder);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );
        let mut pw = PartialWitness::new();
        let header_root = [
            247, 238, 124, 76, 43, 57, 206, 203, 222, 133, 101, 42, 174, 190, 35, 178, 39, 63, 116,
            54, 74, 140, 33, 180, 208, 188, 67, 89, 9, 221, 119, 145,
        ];
        let parent_root = [
            251, 185, 224, 181, 217, 61, 112, 53, 238, 32, 107, 126, 238, 77, 208, 175, 207, 39,
            19, 43, 185, 129, 90, 118, 128, 215, 15, 164, 2, 101, 156, 16,
        ];
        let state_root = [
            186, 82, 121, 59, 237, 9, 80, 140, 75, 81, 16, 245, 93, 129, 213, 136, 55, 10, 63, 169,
            21, 76, 47, 201, 209, 46, 149, 244, 138, 242, 65, 162,
        ];
        let body_root = [
            106, 221, 189, 66, 29, 158, 48, 49, 154, 102, 227, 188, 21, 160, 11, 174, 213, 25, 64,
            209, 113, 24, 176, 156, 83, 108, 138, 77, 68, 42, 239, 0,
        ];
        let slot = 6592564;
        let proposer_index = 310913;
        set_beacon_block_header_target(
            &mut pw,
            &header_root,
            slot,
            proposer_index,
            &parent_root,
            &state_root,
            &body_root,
            &beacon_block_header_target,
        );

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_signing_root() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let num_gates = builder.num_gates();
        let signing_root_target = add_virtual_signing_root_target(&mut builder);
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let slot = 6592564;
        let header_root = [
            247, 238, 124, 76, 43, 57, 206, 203, 222, 133, 101, 42, 174, 190, 35, 178, 39, 63, 116,
            54, 74, 140, 33, 180, 208, 188, 67, 89, 9, 221, 119, 145,
        ];

        let domain = [
            7, 0, 0, 0, 98, 137, 65, 239, 33, 209, 254, 140, 113, 52, 114, 10, 221, 16, 187, 145,
            227, 176, 44, 0, 126, 0, 70, 210, 71, 44, 102, 149,
        ];
        let signing_root = [
            113, 71, 84, 198, 232, 217, 127, 180, 112, 195, 214, 76, 153, 0, 243, 3, 118, 243, 160,
            62, 35, 58, 60, 140, 144, 98, 71, 97, 13, 181, 182, 247,
        ];

        let mut pw = PartialWitness::new();
        set_signing_root_target(
            &mut pw,
            &header_root,
            &domain,
            &signing_root,
            &signing_root_target,
        );

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_verify_finality_branch() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let num_gates = builder.num_gates();

        let finalized_header_index = 105;
        let finalized_header_height = 6;
        let merkle_proof_target = add_verify_merkle_proof_target(
            &mut builder,
            finalized_header_index,
            finalized_header_height,
        );

        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let finalized_header_root = [
            115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21,
            58, 28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
        ];
        let proof = [
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

        let mut pw = PartialWitness::new();
        set_virtual_finality_branch_target(
            &mut pw,
            &finalized_header_root,
            &proof,
            &attested_state_root,
            &merkle_proof_target,
        );

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
