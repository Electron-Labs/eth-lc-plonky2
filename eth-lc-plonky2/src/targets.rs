use crate::merkle_tree_gadget::{
    add_verify_merkle_proof_target, add_virtual_merkle_tree_sha256_target,
    set_verify_merkle_proof_target, VerifyMerkleProofTarget,
};
use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    hash::{
        sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
        CircuitBuilderHash, Hash256Target, HashInputTarget, HashOutputTarget, WitnessHash,
    },
    nonnative::gadgets::biguint::WitnessBigUint,
    u32::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        binary_u32::CircuitBuilderBU32,
        witness::WitnessU32,
    },
};

const FINALIZED_HEADER_INDEX: usize = 105;
const FINALIZED_HEADER_HEIGHT: usize = 6;
const MIN_SYNC_COMMITTEE_PARTICIPANTS: usize = 10;
const FINALITY_THRESHOLD: usize = 342;

pub struct SigningRootTarget {
    pub signing_root: Hash256Target,
    pub header_root: Hash256Target,
    pub domain: Hash256Target,
}
pub struct BeaconBlockHeaderTarget {
    pub header_root: Hash256Target,
    pub slot: Hash256Target,
    pub proposer_index: Hash256Target,
    pub parent_root: Hash256Target,
    pub state_root: Hash256Target,
    pub body_root: Hash256Target,
}

pub struct ContractStateTarget {
    pub curr_contract_state: Hash256Target,
    pub new_contract_state: Hash256Target,
    pub curr_contract_header: Hash256Target,
    pub curr_contract_slot: Hash256Target,
    pub curr_sync_committee_i: Hash256Target,
    pub curr_sync_committee_ii: Hash256Target,
    pub new_contract_header: Hash256Target,
    pub new_contract_slot: Hash256Target,
    pub new_sync_committee_i: Hash256Target,
    pub new_sync_committee_ii: Hash256Target,
}

pub struct ProofTarget {
    pub signing_root: Hash256Target,
    pub attested_header_root: Hash256Target,
    pub domain: Hash256Target,
    pub attested_slot: Hash256Target,
    pub attested_proposer_index: Hash256Target,
    pub attested_parent_root: Hash256Target,
    pub attested_state_root: Hash256Target,
    pub attested_body_root: Hash256Target,
    pub finalized_header_root: Hash256Target,
    pub finality_branch: Vec<Hash256Target>,
    pub finalized_slot: Hash256Target,
    pub finalized_proposer_index: Hash256Target,
    pub finalized_parent_root: Hash256Target,
    pub finalized_state_root: Hash256Target,
    pub finalized_body_root: Hash256Target,
    pub curr_contract_state: Hash256Target,
    pub curr_contract_slot: Hash256Target,
    pub curr_contract_header: Hash256Target,
    pub curr_sync_committee_i: Hash256Target, // TODO: rename; add comments
    pub curr_sync_committee_ii: Hash256Target,
    pub new_contract_state: Hash256Target,
    pub new_sync_committee_i: Hash256Target,
    pub new_sync_committee_ii: Hash256Target,
    pub participation: Hash256Target,
}

pub struct BiguintHash256ConnectTarget {
    big: BigUintTarget,
    h256: Hash256Target,
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

pub fn add_virtual_contract_state_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ContractStateTarget {
    let curr_contract_state = builder.add_virtual_hash256_target();
    let new_contract_state = builder.add_virtual_hash256_target();
    let curr_contract_header = builder.add_virtual_hash256_target();
    let curr_contract_slot = builder.add_virtual_hash256_target();
    let curr_sync_committee_i = builder.add_virtual_hash256_target();
    let curr_sync_committee_ii = builder.add_virtual_hash256_target();
    let new_contract_header = builder.add_virtual_hash256_target();
    let new_contract_slot = builder.add_virtual_hash256_target();
    let new_sync_committee_i = builder.add_virtual_hash256_target();
    let new_sync_committee_ii = builder.add_virtual_hash256_target();

    let curr_merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 2);
    builder.connect_hash256(curr_contract_header, curr_merkle_tree_target.leaves[0]);
    builder.connect_hash256(curr_contract_slot, curr_merkle_tree_target.leaves[1]);
    builder.connect_hash256(curr_sync_committee_i, curr_merkle_tree_target.leaves[2]);
    builder.connect_hash256(curr_sync_committee_ii, curr_merkle_tree_target.leaves[3]);

    let zero_u32 = builder.zero_u32();
    for &target in curr_merkle_tree_target.leaves[4..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    let new_merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 2);
    builder.connect_hash256(new_contract_header, new_merkle_tree_target.leaves[0]);
    builder.connect_hash256(new_contract_slot, new_merkle_tree_target.leaves[1]);
    builder.connect_hash256(new_sync_committee_i, new_merkle_tree_target.leaves[2]);
    builder.connect_hash256(new_sync_committee_ii, new_merkle_tree_target.leaves[3]);

    let zero_u32 = builder.zero_u32();
    for &target in new_merkle_tree_target.leaves[4..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    builder.connect_hash256(curr_contract_state, curr_merkle_tree_target.root);
    builder.connect_hash256(new_contract_state, new_merkle_tree_target.root);

    ContractStateTarget {
        curr_contract_state,
        new_contract_state,
        curr_contract_header,
        curr_contract_slot,
        curr_sync_committee_i,
        curr_sync_committee_ii,
        new_contract_header,
        new_contract_slot,
        new_sync_committee_i,
        new_sync_committee_ii,
    }
}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    // TODO:
    // builder._if(curr_period): set target to committee_i
    // else if (next_period) : set target to committee_ii
    // else: invalid

    let signing_root = builder.add_virtual_hash256_target();
    let attested_header_root = builder.add_virtual_hash256_target();
    let domain = builder.add_virtual_hash256_target();
    let attested_slot = builder.add_virtual_hash256_target();
    let attested_proposer_index = builder.add_virtual_hash256_target();
    let attested_parent_root = builder.add_virtual_hash256_target();
    let attested_state_root = builder.add_virtual_hash256_target();
    let attested_body_root = builder.add_virtual_hash256_target();
    let finalized_header_root = builder.add_virtual_hash256_target();
    let finalized_slot = builder.add_virtual_hash256_target();
    let finalized_proposer_index = builder.add_virtual_hash256_target();
    let finalized_parent_root = builder.add_virtual_hash256_target();
    let finalized_state_root = builder.add_virtual_hash256_target();
    let finalized_body_root = builder.add_virtual_hash256_target();
    let finality_branch = (0..FINALIZED_HEADER_HEIGHT)
        .map(|_| builder.add_virtual_hash256_target())
        .collect::<Vec<Hash256Target>>();

    let curr_contract_state = builder.add_virtual_hash256_target();
    let curr_contract_header = builder.add_virtual_hash256_target();
    let curr_contract_slot = builder.add_virtual_hash256_target();
    let curr_sync_committee_i = builder.add_virtual_hash256_target();
    let curr_sync_committee_ii = builder.add_virtual_hash256_target();
    let new_contract_state = builder.add_virtual_hash256_target();
    let new_sync_committee_i = builder.add_virtual_hash256_target();
    let new_sync_committee_ii = builder.add_virtual_hash256_target();
    let participation = builder.add_virtual_hash256_target();

    // 2. [altair] process_light_client_update: Verify Merkle branch of header
    let signing_root_target = add_virtual_signing_root_target(builder);
    let attested_beacon_block_header_target = add_virtual_beacon_block_header_target(builder);
    let finalized_beacon_block_header_target = add_virtual_beacon_block_header_target(builder);
    let finality_branch_target =
        add_verify_merkle_proof_target(builder, FINALIZED_HEADER_INDEX, FINALIZED_HEADER_HEIGHT);

    let contract_state_target = add_virtual_contract_state_target(builder);

    // *** signing root ***
    builder.connect_hash256(signing_root, signing_root_target.signing_root);
    builder.connect_hash256(attested_header_root, signing_root_target.header_root);
    builder.connect_hash256(domain, signing_root_target.domain);

    // *** attested block header ***
    builder.connect_hash256(
        attested_body_root,
        attested_beacon_block_header_target.body_root,
    );
    builder.connect_hash256(
        attested_header_root,
        attested_beacon_block_header_target.header_root,
    );
    builder.connect_hash256(
        attested_parent_root,
        attested_beacon_block_header_target.parent_root,
    );
    builder.connect_hash256(
        attested_proposer_index,
        attested_beacon_block_header_target.proposer_index,
    );
    builder.connect_hash256(attested_slot, attested_beacon_block_header_target.slot);
    builder.connect_hash256(
        attested_state_root,
        attested_beacon_block_header_target.state_root,
    );

    // *** finalized block header ***
    builder.connect_hash256(
        finalized_body_root,
        finalized_beacon_block_header_target.body_root,
    );
    builder.connect_hash256(
        finalized_header_root,
        finalized_beacon_block_header_target.header_root,
    );
    builder.connect_hash256(
        finalized_parent_root,
        finalized_beacon_block_header_target.parent_root,
    );
    builder.connect_hash256(
        finalized_proposer_index,
        finalized_beacon_block_header_target.proposer_index,
    );
    builder.connect_hash256(finalized_slot, finalized_beacon_block_header_target.slot);
    builder.connect_hash256(
        finalized_state_root,
        finalized_beacon_block_header_target.state_root,
    );

    // *** finality branch ***
    builder.connect_hash256(finalized_header_root, finality_branch_target.leaf);
    builder.connect_hash256(attested_state_root, finality_branch_target.root);
    (0..FINALIZED_HEADER_HEIGHT)
        .into_iter()
        .for_each(|i| builder.connect_hash256(finality_branch[i], finality_branch_target.proof[i]));

    // *** contract state ***
    builder.connect_hash256(
        curr_contract_header,
        contract_state_target.curr_contract_header,
    );
    builder.connect_hash256(curr_contract_slot, contract_state_target.curr_contract_slot);
    builder.connect_hash256(
        curr_sync_committee_i,
        contract_state_target.curr_sync_committee_i,
    );
    builder.connect_hash256(
        curr_sync_committee_ii,
        contract_state_target.curr_sync_committee_ii,
    );
    builder.connect_hash256(
        finalized_header_root,
        contract_state_target.new_contract_header,
    );
    builder.connect_hash256(finalized_slot, contract_state_target.new_contract_slot);
    builder.connect_hash256(
        new_sync_committee_i,
        contract_state_target.new_sync_committee_i,
    );
    builder.connect_hash256(
        new_sync_committee_ii,
        contract_state_target.new_sync_committee_ii,
    );

    ProofTarget {
        signing_root,
        attested_header_root,
        domain,
        attested_slot,
        attested_proposer_index,
        attested_parent_root,
        attested_state_root,
        attested_body_root,
        finalized_header_root,
        finality_branch,
        finalized_slot,
        finalized_proposer_index,
        finalized_parent_root,
        finalized_state_root,
        finalized_body_root,
        curr_contract_state,
        curr_contract_slot,
        curr_contract_header,
        curr_sync_committee_i,
        curr_sync_committee_ii,
        new_contract_state,
        new_sync_committee_i,
        new_sync_committee_ii,
        participation,
    }
}

pub fn add_virtual_biguint_hash256_connect_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BiguintHash256ConnectTarget {
    let big = builder.add_virtual_biguint_target(8);
    let h256 = builder.add_virtual_hash256_target();

    for i in 0..8 {
        let limb_big = big.get_limb(i);
        let limb_h256 = h256[i];
        let bit_targets_big = builder.split_le_base::<2>(limb_big.0, 32);
        let bit_targets_h256 = builder.split_le_base::<2>(limb_h256.0, 32);
        (0..4).for_each(|i| {
            (0..8).for_each(|j| {
                // TODO: currently checking at bit level, do it at byte level
                builder.connect(bit_targets_big[8 * i + j], bit_targets_h256[24 - 8 * i + j])
            })
        });
    }

    BiguintHash256ConnectTarget { big, h256 }
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

pub fn set_finality_branch_target<F: RichField, W: WitnessHashSha2<F>>(
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

pub fn set_contract_state_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    curr_contract_state: &[u8; 32],
    curr_contract_header: &[u8; 32],
    curr_contract_slot: u64,
    curr_sync_committee_i: &[u8; 32],
    curr_sync_committee_ii: &[u8; 32],
    new_contract_state: &[u8; 32],
    new_contract_header: &[u8; 32],
    new_contract_slot: u64,
    new_sync_committee_i: &[u8; 32],
    new_sync_committee_ii: &[u8; 32],
    contract_state_target: &ContractStateTarget,
) {
    witness.set_hash256_target(
        &contract_state_target.curr_contract_state,
        &curr_contract_state,
    );
    witness.set_hash256_target(
        &contract_state_target.curr_contract_header,
        &curr_contract_header,
    );
    let mut curr_contract_slot_bytes = [0u8; 32];
    curr_contract_slot_bytes[0..8].copy_from_slice(&curr_contract_slot.to_le_bytes());
    witness.set_hash256_target(
        &contract_state_target.curr_contract_slot,
        &curr_contract_slot_bytes,
    );
    witness.set_hash256_target(
        &contract_state_target.curr_sync_committee_i,
        &curr_sync_committee_i,
    );
    witness.set_hash256_target(
        &contract_state_target.curr_sync_committee_ii,
        &curr_sync_committee_ii,
    );

    witness.set_hash256_target(
        &contract_state_target.new_contract_state,
        &new_contract_state,
    );
    witness.set_hash256_target(
        &contract_state_target.new_contract_header,
        &new_contract_header,
    );

    let mut new_contract_slot_bytes = [0u8; 32];
    new_contract_slot_bytes[0..8].copy_from_slice(&new_contract_slot.to_le_bytes());
    witness.set_hash256_target(
        &contract_state_target.new_contract_slot,
        &new_contract_slot_bytes,
    );
    witness.set_hash256_target(
        &contract_state_target.new_sync_committee_i,
        &new_sync_committee_i,
    );
    witness.set_hash256_target(
        &contract_state_target.new_sync_committee_ii,
        &new_sync_committee_ii,
    );
}

pub fn set_proof_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    signing_root: &[u8; 32],
    attested_header_root: &[u8; 32],
    domain: &[u8; 32],
    attested_slot: u64,
    attested_proposer_index: u64,
    attested_parent_root: &[u8; 32],
    attested_state_root: &[u8; 32],
    attested_body_root: &[u8; 32],
    finalized_header_root: &[u8; 32],
    finality_branch: &[[u8; 32]; 6],
    finalized_slot: u64,
    finalized_proposer_index: u64,
    finalized_parent_root: &[u8; 32],
    finalized_state_root: &[u8; 32],
    finalized_body_root: &[u8; 32],
    curr_contract_state: &[u8; 32],
    new_contract_state: &[u8; 32],
    curr_contract_header: &[u8; 32],
    curr_contract_slot: u64,
    curr_sync_committee_i: &[u8; 32],
    curr_sync_committee_ii: &[u8; 32],
    new_sync_committee_i: &[u8; 32],
    new_sync_committee_ii: &[u8; 32],
    participation: u64,
    target: &ProofTarget,
) {
    witness.set_hash256_target(&target.attested_header_root, attested_header_root);
    witness.set_hash256_target(&target.domain, domain);
    witness.set_hash256_target(&target.signing_root, signing_root);

    witness.set_hash256_target(&target.attested_parent_root, attested_parent_root);
    witness.set_hash256_target(&target.attested_state_root, attested_state_root);
    witness.set_hash256_target(&target.attested_body_root, attested_body_root);

    let mut attested_slot_bytes = [0u8; 32];
    attested_slot_bytes[0..8].copy_from_slice(&attested_slot.to_le_bytes());
    witness.set_hash256_target(&target.attested_slot, &attested_slot_bytes);

    let mut attested_proposer_index_bytes = [0u8; 32];
    attested_proposer_index_bytes[0..8].copy_from_slice(&attested_proposer_index.to_le_bytes());
    witness.set_hash256_target(
        &target.attested_proposer_index,
        &attested_proposer_index_bytes,
    );

    witness.set_hash256_target(&target.finalized_header_root, finalized_header_root);
    witness.set_hash256_target(&target.finalized_parent_root, finalized_parent_root);
    witness.set_hash256_target(&target.finalized_state_root, finalized_state_root);
    witness.set_hash256_target(&target.finalized_body_root, finalized_body_root);

    let mut finalized_slot_bytes = [0u8; 32];
    finalized_slot_bytes[0..8].copy_from_slice(&finalized_slot.to_le_bytes());
    witness.set_hash256_target(&target.finalized_slot, &finalized_slot_bytes);

    let mut finalized_proposer_index_bytes = [0u8; 32];
    finalized_proposer_index_bytes[0..8].copy_from_slice(&finalized_proposer_index.to_le_bytes());
    witness.set_hash256_target(
        &target.finalized_proposer_index,
        &finalized_proposer_index_bytes,
    );

    (0..FINALIZED_HEADER_HEIGHT)
        .for_each(|i| witness.set_hash256_target(&target.finality_branch[i], &finality_branch[i]));

    let mut curr_contract_slot_bytes = [0u8; 32];
    curr_contract_slot_bytes[0..8].copy_from_slice(&curr_contract_slot.to_le_bytes());
    witness.set_hash256_target(&target.curr_contract_slot, &curr_contract_slot_bytes);

    let mut participation_bytes = [0u8; 32];
    participation_bytes[0..8].copy_from_slice(&participation.to_le_bytes());
    witness.set_hash256_target(&target.participation, &participation_bytes);

    witness.set_hash256_target(&target.curr_contract_state, &curr_contract_state);
    witness.set_hash256_target(&target.curr_contract_header, &curr_contract_header);
    witness.set_hash256_target(&target.curr_sync_committee_i, &curr_sync_committee_i);
    witness.set_hash256_target(&target.curr_sync_committee_ii, &curr_sync_committee_ii);
    witness.set_hash256_target(&target.new_contract_state, &new_contract_state);
    witness.set_hash256_target(&target.new_sync_committee_i, &new_sync_committee_i);
    witness.set_hash256_target(&target.new_sync_committee_ii, &new_sync_committee_ii);
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree_gadget::add_verify_merkle_proof_target;
    use crate::targets::{
        add_virtual_beacon_block_header_target, add_virtual_biguint_hash256_connect_target,
        add_virtual_contract_state_target, add_virtual_signing_root_target,
        set_beacon_block_header_target, set_contract_state_target, set_finality_branch_target,
        set_signing_root_target, FINALIZED_HEADER_HEIGHT, FINALIZED_HEADER_INDEX,
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
    use plonky2_crypto::{
        biguint::{BigUintTarget, CircuitBuilderBiguint},
        hash::{CircuitBuilderHash, WitnessHash},
        nonnative::gadgets::biguint::WitnessBigUint,
        u32::{
            arithmetic_u32::{CircuitBuilderU32, U32Target},
            witness::WitnessU32,
        },
    };

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

        let mut pw = PartialWitness::new();
        set_signing_root_target(
            &mut pw,
            &attested_header_root,
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
    fn test_verify_finality_branch() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let num_gates = builder.num_gates();

        let merkle_proof_target = add_verify_merkle_proof_target(
            &mut builder,
            FINALIZED_HEADER_INDEX,
            FINALIZED_HEADER_HEIGHT,
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

        let mut pw = PartialWitness::new();
        set_finality_branch_target(
            &mut pw,
            &finalized_header_root,
            &finality_branch,
            &attested_state_root,
            &merkle_proof_target,
        );

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_contract_state() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let contract_state_target = add_virtual_contract_state_target(&mut builder);

        let curr_contract_header = [
            115, 117, 208, 140, 31, 202, 241, 87, 161, 53, 213, 45, 186, 177, 206, 189, 224, 21,
            58, 28, 142, 128, 12, 189, 218, 111, 189, 237, 87, 148, 52, 30,
        ];
        let new_contract_header = [
            181, 47, 90, 74, 144, 147, 36, 105, 62, 96, 18, 13, 201, 106, 185, 87, 99, 0, 172, 243,
            251, 239, 179, 67, 235, 186, 53, 70, 1, 99, 36, 59,
        ];
        let curr_contract_slot = 6588416;
        let new_contract_slot = 6594720;

        let mut curr_sync_committee_i = [0u8; 32];
        curr_sync_committee_i[0] = 10;
        let mut curr_sync_committee_ii = [0u8; 32];
        curr_sync_committee_ii[20] = 70;

        let mut new_sync_committee_i = [0u8; 32];
        new_sync_committee_i[0] = 10;
        let mut new_sync_committee_ii = [0u8; 32];
        new_sync_committee_ii[20] = 70;

        let curr_contract_state = [
            184, 125, 255, 223, 248, 134, 92, 238, 197, 185, 188, 16, 90, 177, 15, 38, 36, 56, 168,
            111, 27, 58, 138, 200, 137, 14, 185, 195, 135, 70, 115, 55,
        ];
        let new_contract_state = [
            248, 94, 17, 117, 76, 129, 51, 3, 205, 253, 251, 77, 214, 130, 186, 45, 159, 36, 3,
            207, 18, 28, 69, 31, 108, 98, 31, 64, 45, 121, 43, 142,
        ];

        let mut pw = PartialWitness::new();
        set_contract_state_target(
            &mut pw,
            &curr_contract_state,
            &curr_contract_header,
            curr_contract_slot,
            &curr_sync_committee_i,
            &curr_sync_committee_ii,
            &new_contract_state,
            &new_contract_header,
            new_contract_slot,
            &new_sync_committee_i,
            &new_sync_committee_ii,
            &contract_state_target,
        );

        let data = builder.build::<C>();

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_biguint_hash256_target_connect() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let slot: u64 = 25000;

        let biguint_hash256_connect_target =
            add_virtual_biguint_hash256_connect_target(&mut builder);
        let mut pw = PartialWitness::new();

        let mut slot_bytes = [0u8; 32];
        slot_bytes[0..8].copy_from_slice(&slot.to_le_bytes());
        pw.set_hash256_target(&biguint_hash256_connect_target.h256, &slot_bytes);

        let big_slot = BigUint::from_u64(slot).unwrap();
        pw.set_biguint_target(&biguint_hash256_connect_target.big, &big_slot);

        let data = builder.build::<C>();

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
