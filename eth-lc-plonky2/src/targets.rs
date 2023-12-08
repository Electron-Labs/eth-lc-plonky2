// TODO: reorder arguments in all `builder.connect...`
use crate::merkle_tree_gadget::{
    add_verify_merkle_proof_conditional_target, add_verify_merkle_proof_target,
    add_virtual_merkle_tree_sha256_target,
};
use crate::utils::{add_virtual_is_equal_big_uint_target, add_virtual_biguint_hash256_connect_target};
use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    hash::{sha256::WitnessHashSha2, CircuitBuilderHash, Hash256Target, WitnessHash},
    nonnative::gadgets::biguint::WitnessBigUint,
    u32::arithmetic_u32::CircuitBuilderU32,
};

pub const FINALIZED_HEADER_INDEX: usize = 105;
pub const FINALIZED_HEADER_HEIGHT: usize = 6;
pub const SYNC_COMMITTEE_HEIGHT: usize = 5;
pub const SYNC_COMMITTEE_INDEX: usize = 55;
pub const FINALITY_THRESHOLD: usize = 342;
pub const N_SLOTS_PER_PERIOD: usize = 8192;

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

// TODO: reorder varaiables
pub struct ContractStateTarget {
    pub cur_state: Hash256Target,
    pub new_state: Hash256Target,
    pub cur_header: Hash256Target,
    pub cur_slot: Hash256Target,
    pub cur_sync_committee_i: Hash256Target, // sync committee ssz corresponding to the period of `cur_slot`
    pub cur_sync_committee_ii: Hash256Target, // Sync committee ssz corresponding to the period next of `cur_slot`
    pub new_header: Hash256Target,
    pub new_slot: Hash256Target,
    pub new_sync_committee_i: Hash256Target, // sync committee ssz corresponding the to period of `new_slot`
    pub new_sync_committee_ii: Hash256Target, // sync committee ssz corresponding to the period next of `new_slot`
}

pub struct CurSyncCommitteeTarget {
    pub cur_slot_big: BigUintTarget,
    pub attested_slot_big: BigUintTarget,
    pub cur_sync_committee_i: Hash256Target,
    pub cur_sync_committee_ii: Hash256Target,
    pub is_attested_from_next_period: BoolTarget,
    pub sync_committee_for_attested_slot: Hash256Target,
}

pub struct UpdateSyncCommitteeTarget {
    pub is_attested_from_next_period: BoolTarget,
    pub cur_sync_committee_i: Hash256Target,
    pub cur_sync_committee_ii: Hash256Target,
    pub new_sync_committee_i: Hash256Target,
    pub new_sync_committee_ii: Hash256Target,
    pub finalized_state_root: Hash256Target,
    pub new_sync_committee_ii_branch: Vec<Hash256Target>,
}

pub struct UpdateValidityTarget {
    pub cur_slot_big: BigUintTarget,
    pub finalized_slot_big: BigUintTarget,
    pub participation_big: BigUintTarget,
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
    pub cur_state: Hash256Target,
    pub cur_slot: Hash256Target,
    pub cur_header: Hash256Target,
    pub cur_sync_committee_i: Hash256Target,
    pub cur_sync_committee_ii: Hash256Target,
    pub new_state: Hash256Target,
    pub new_sync_committee_i: Hash256Target,
    pub new_sync_committee_ii: Hash256Target,
    pub participation: Hash256Target,
    pub cur_slot_big: BigUintTarget,
    pub attested_slot_big: BigUintTarget,
    pub new_sync_committee_ii_branch: Vec<Hash256Target>,
    pub finalized_slot_big: BigUintTarget,
    pub participation_big: BigUintTarget,
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

pub fn add_virtual_sync_committee_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> CurSyncCommitteeTarget {
    let attested_slot_big = builder.add_virtual_biguint_target(8);
    let cur_slot_big = builder.add_virtual_biguint_target(8);
    let cur_sync_committee_i = builder.add_virtual_hash256_target();
    let cur_sync_committee_ii = builder.add_virtual_hash256_target();
    let sync_committee_for_attested_slot = builder.add_virtual_hash256_target();

    let one_bool_target = builder.constant_bool(true);
    let one_big_target = builder.constant_biguint(&BigUint::from_u16(1).unwrap());
    let n_slot_big = BigUint::from_usize(N_SLOTS_PER_PERIOD).unwrap();
    let n_slot_target = builder.constant_biguint(&n_slot_big);

    let (attested_period, _) = builder.div_rem_biguint(&attested_slot_big, &n_slot_target);
    let (cur_period, _) = builder.div_rem_biguint(&cur_slot_big, &n_slot_target);
    let next_period = builder.add_biguint(&cur_period, &one_big_target);

    let is_attested_from_cur_period = add_virtual_is_equal_big_uint_target(builder);
    builder.connect_biguint(&is_attested_from_cur_period.big1, &attested_period);
    builder.connect_biguint(&is_attested_from_cur_period.big2, &cur_period);

    let is_attested_from_next_period = add_virtual_is_equal_big_uint_target(builder);
    builder.connect_biguint(&is_attested_from_next_period.big1, &attested_period);
    builder.connect_biguint(&is_attested_from_next_period.big2, &next_period);

    // ensure the attested slot is either from cur period or next period
    let from_cur_or_next_period = builder.or(
        is_attested_from_cur_period.result,
        is_attested_from_next_period.result,
    );
    builder.connect(from_cur_or_next_period.target, one_bool_target.target);

    // set sync committee (corresponding to attested_period)
    (0..8).for_each(|i| {
        let if_result = builder._if(
            is_attested_from_cur_period.result,
            cur_sync_committee_i[i].0,
            cur_sync_committee_ii[i].0,
        );
        builder.connect(sync_committee_for_attested_slot[i].0, if_result)
    });

    CurSyncCommitteeTarget {
        attested_slot_big,
        cur_slot_big,
        cur_sync_committee_i,
        cur_sync_committee_ii,
        is_attested_from_next_period: is_attested_from_next_period.result,
        sync_committee_for_attested_slot,
    }
}

pub fn add_virtual_update_sync_committe_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> UpdateSyncCommitteeTarget {
    let is_attested_from_next_period = builder.add_virtual_bool_target_safe();
    let cur_sync_committee_i = builder.add_virtual_hash256_target();
    let cur_sync_committee_ii = builder.add_virtual_hash256_target();
    let new_sync_committee_i = builder.add_virtual_hash256_target();
    let new_sync_committee_ii = builder.add_virtual_hash256_target();
    let finalized_state_root = builder.add_virtual_hash256_target();
    let new_sync_committee_ii_branch = (0..SYNC_COMMITTEE_HEIGHT)
        .map(|_| builder.add_virtual_hash256_target())
        .collect::<Vec<Hash256Target>>();

    let sync_committee_branch_target = add_verify_merkle_proof_conditional_target(
        builder,
        SYNC_COMMITTEE_INDEX,
        SYNC_COMMITTEE_HEIGHT,
    );

    // conditional merkle leaf verification
    builder.connect_hash256(
        sync_committee_branch_target.leaf,
        new_sync_committee_ii,
    );
    (0..SYNC_COMMITTEE_HEIGHT).into_iter().for_each(|i| {
        builder.connect_hash256(
            sync_committee_branch_target.proof[i],
            new_sync_committee_ii_branch[i],
        )
    });
    builder.connect_hash256(sync_committee_branch_target.root, finalized_state_root);
    builder.connect(
        sync_committee_branch_target.v.target,
        is_attested_from_next_period.target,
    );

    // `cur_sync_committee_i` and `new_sync_committee_i` should not differ if attested slot is not from the next period
    let is_attested_not_from_next_period = builder.not(is_attested_from_next_period);
    (0..8).for_each(|i| {
        let a = builder.mul(
            cur_sync_committee_i[i].0,
            is_attested_not_from_next_period.target,
        );
        let b = builder.mul(
            new_sync_committee_i[i].0,
            is_attested_not_from_next_period.target,
        );
        builder.connect(a, b);
    });

    // `new_sync_committee_i` should be equal to `cur_sync_committee_ii` if attested slot is from the next period
    (0..8).for_each(|i| {
        let a = builder.mul(
            cur_sync_committee_ii[i].0,
            is_attested_from_next_period.target,
        );
        let b = builder.mul(
            new_sync_committee_i[i].0,
            is_attested_from_next_period.target,
        );
        builder.connect(a, b);
    });

    UpdateSyncCommitteeTarget {
        is_attested_from_next_period,
        cur_sync_committee_i,
        cur_sync_committee_ii,
        new_sync_committee_i,
        new_sync_committee_ii,
        finalized_state_root,
        new_sync_committee_ii_branch,
    }
}

pub fn add_virtual_update_validity_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> UpdateValidityTarget {
    let cur_slot_big = builder.add_virtual_biguint_target(8);
    let finalized_slot_big = builder.add_virtual_biguint_target(8);
    let participation_big = builder.add_virtual_biguint_target(8);

    let one = builder.one();
    let zero = builder.zero();
    let mut result: BoolTarget;

    // checks if  curr_contract_slot <= finalized_slot
    result = builder.cmp_biguint(&cur_slot_big, &finalized_slot_big);
    builder.connect(result.target, one);

    // ensure enough participants
    // checks if participation <= FINALITY_THRESHOLD
    let finality_threshold_target =
        builder.constant_biguint(&BigUint::from_usize(FINALITY_THRESHOLD).unwrap());
    result = builder.cmp_biguint(&participation_big, &finality_threshold_target);
    builder.connect(result.target, zero);

    UpdateValidityTarget {
        cur_slot_big,
        finalized_slot_big,
        participation_big,
    }
}

pub fn add_virtual_contract_state_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ContractStateTarget {
    let cur_state = builder.add_virtual_hash256_target();
    let new_state = builder.add_virtual_hash256_target();
    let cur_slot = builder.add_virtual_hash256_target();
    let cur_header = builder.add_virtual_hash256_target();
    let cur_sync_committee_i = builder.add_virtual_hash256_target();
    let cur_sync_committee_ii = builder.add_virtual_hash256_target();
    let new_slot = builder.add_virtual_hash256_target();
    let new_header = builder.add_virtual_hash256_target();
    let new_sync_committee_i = builder.add_virtual_hash256_target();
    let new_sync_committee_ii = builder.add_virtual_hash256_target();

    let cur_merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 2);
    builder.connect_hash256(cur_slot, cur_merkle_tree_target.leaves[0]);
    builder.connect_hash256(cur_header, cur_merkle_tree_target.leaves[1]);
    builder.connect_hash256(
        cur_sync_committee_i,
        cur_merkle_tree_target.leaves[2],
    );
    builder.connect_hash256(
        cur_sync_committee_ii,
        cur_merkle_tree_target.leaves[3],
    );

    let zero_u32 = builder.zero_u32();
    for &target in cur_merkle_tree_target.leaves[4..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    let new_merkle_tree_target = add_virtual_merkle_tree_sha256_target(builder, 2);
    builder.connect_hash256(new_slot, new_merkle_tree_target.leaves[0]);
    builder.connect_hash256(new_header, new_merkle_tree_target.leaves[1]);
    builder.connect_hash256(
        new_sync_committee_i,
        new_merkle_tree_target.leaves[2],
    );
    builder.connect_hash256(
        new_sync_committee_ii,
        new_merkle_tree_target.leaves[3],
    );

    let zero_u32 = builder.zero_u32();
    for &target in new_merkle_tree_target.leaves[4..].iter() {
        for &limb in target.iter() {
            builder.connect_u32(limb, zero_u32);
        }
    }

    builder.connect_hash256(cur_state, cur_merkle_tree_target.root);
    builder.connect_hash256(new_state, new_merkle_tree_target.root);

    ContractStateTarget {
        cur_state,
        new_state,
        cur_header,
        cur_slot,
        cur_sync_committee_i,
        cur_sync_committee_ii,
        new_header,
        new_slot,
        new_sync_committee_i,
        new_sync_committee_ii,
    }
}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    let signing_root = builder.add_virtual_hash256_target();
    let domain = builder.add_virtual_hash256_target();

    let attested_header_root = builder.add_virtual_hash256_target();
    let attested_slot = builder.add_virtual_hash256_target();
    let attested_slot_big = builder.add_virtual_biguint_target(8);
    let attested_proposer_index = builder.add_virtual_hash256_target();
    let attested_parent_root = builder.add_virtual_hash256_target();
    let attested_state_root = builder.add_virtual_hash256_target();
    let attested_body_root = builder.add_virtual_hash256_target();
    let finalized_header_root = builder.add_virtual_hash256_target();
    let finalized_slot = builder.add_virtual_hash256_target();
    let finalized_slot_big = builder.add_virtual_biguint_target(8);
    let finalized_proposer_index = builder.add_virtual_hash256_target();
    let finalized_parent_root = builder.add_virtual_hash256_target();
    let finalized_state_root = builder.add_virtual_hash256_target();
    let finalized_body_root = builder.add_virtual_hash256_target();
    let finality_branch = (0..FINALIZED_HEADER_HEIGHT)
    .map(|_| builder.add_virtual_hash256_target())
    .collect::<Vec<Hash256Target>>();
    let participation_big = builder.add_virtual_biguint_target(8);

    let cur_state = builder.add_virtual_hash256_target();
    let cur_slot = builder.add_virtual_hash256_target();
    let cur_slot_big = builder.add_virtual_biguint_target(8);
    let cur_header = builder.add_virtual_hash256_target();
    let cur_sync_committee_i = builder.add_virtual_hash256_target();
    let cur_sync_committee_ii = builder.add_virtual_hash256_target();
    let new_state = builder.add_virtual_hash256_target();
    let new_sync_committee_i = builder.add_virtual_hash256_target();
    let new_sync_committee_ii = builder.add_virtual_hash256_target();
    let participation = builder.add_virtual_hash256_target();
    let new_sync_committee_ii_branch = (0..SYNC_COMMITTEE_HEIGHT)
        .map(|_| builder.add_virtual_hash256_target())
        .collect::<Vec<Hash256Target>>();

    // 2. [altair] process_light_client_update: Verify Merkle branch of header
    let signing_root_target = add_virtual_signing_root_target(builder);
    let attested_beacon_block_header_target = add_virtual_beacon_block_header_target(builder);
    let finalized_beacon_block_header_target = add_virtual_beacon_block_header_target(builder);
    let finality_branch_target =
        add_verify_merkle_proof_target(builder, FINALIZED_HEADER_INDEX, FINALIZED_HEADER_HEIGHT);

    let contract_state_target = add_virtual_contract_state_target(builder);
    let sync_committee_target = add_virtual_sync_committee_target(builder);
    let update_sync_committe_target = add_virtual_update_sync_committe_target(builder);

    // 1. [altair] process_light_client_update: Basic validation;
    // 4. [altair] process_light_client_update: : More basic validation + check if 2/3 quorum is reached
    let update_validity_target = add_virtual_update_validity_target(builder);

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


    // *** finality branch ***
    builder.connect_hash256(finalized_header_root, finality_branch_target.leaf);
    builder.connect_hash256(attested_state_root, finality_branch_target.root);
    (0..FINALIZED_HEADER_HEIGHT)
        .into_iter()
        .for_each(|i| builder.connect_hash256(finality_branch[i], finality_branch_target.proof[i]));


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


    // *** sync committee ***
    builder.connect_biguint(
        &sync_committee_target.cur_slot_big,
        &cur_slot_big,
    );
    builder.connect_biguint(&sync_committee_target.attested_slot_big, &attested_slot_big);
    builder.connect_hash256(
        sync_committee_target.cur_sync_committee_i,
        cur_sync_committee_i,
    );
    builder.connect_hash256(
        sync_committee_target.cur_sync_committee_ii,
        cur_sync_committee_ii,
    );
    // TODO: use sync_committee_target.sync_committee_for_attested_slot for signature verification


    // *** update sync committee ***
    builder.connect(
        update_sync_committe_target
            .is_attested_from_next_period
            .target,
        sync_committee_target.is_attested_from_next_period.target,
    );
    builder.connect_hash256(
        update_sync_committe_target.cur_sync_committee_i,
        cur_sync_committee_i,
    );
    builder.connect_hash256(
        update_sync_committe_target.cur_sync_committee_ii,
        cur_sync_committee_ii,
    );
    builder.connect_hash256(
        update_sync_committe_target.new_sync_committee_i,
        new_sync_committee_i,
    );
    builder.connect_hash256(
        update_sync_committe_target.new_sync_committee_ii,
        new_sync_committee_ii,
    );
    builder.connect_hash256(
        update_sync_committe_target.finalized_state_root,
        finalized_state_root,
    );
    (0..SYNC_COMMITTEE_HEIGHT).into_iter().for_each(|i| {
        builder.connect_hash256(
            update_sync_committe_target.new_sync_committee_ii_branch[i],
            new_sync_committee_ii_branch[i],
        )
    });


    // *** update validity ***
    builder.connect_biguint(
        &update_validity_target.cur_slot_big,
        &cur_slot_big,
    );
    builder.connect_biguint(
        &update_validity_target.finalized_slot_big,
        &finalized_slot_big,
    );
    builder.connect_biguint(
        &update_validity_target.participation_big,
        &participation_big,
    );


    // *** contract state ***
    builder.connect_hash256(
        cur_state,
        contract_state_target.cur_state,
    );
    builder.connect_hash256(
        new_state,
        contract_state_target.new_state,
    );
    builder.connect_hash256(
        cur_header,
        contract_state_target.cur_header,
    );
    builder.connect_hash256(cur_slot, contract_state_target.cur_slot);
    builder.connect_hash256(
        cur_sync_committee_i,
        contract_state_target.cur_sync_committee_i,
    );
    builder.connect_hash256(
        cur_sync_committee_ii,
        contract_state_target.cur_sync_committee_ii,
    );
    builder.connect_hash256(
        finalized_header_root,
        contract_state_target.new_header,
    );
    builder.connect_hash256(finalized_slot, contract_state_target.new_slot);
    builder.connect_hash256(
        new_sync_committee_i,
        contract_state_target.new_sync_committee_i,
    );
    builder.connect_hash256(
        new_sync_committee_ii,
        contract_state_target.new_sync_committee_ii,
    );


    // *** make neccessary connections ***
    // connect `cur_slot_big` and `cur_slot`
    let connect_contract_slot = add_virtual_biguint_hash256_connect_target(builder);
    builder.connect_hash256(connect_contract_slot.h256, cur_slot);
    builder.connect_biguint(&connect_contract_slot.big, &cur_slot_big);

    // connect `attested_slot_big` and `attested_slot`
    let connect_attested_slot = add_virtual_biguint_hash256_connect_target(builder);
    builder.connect_hash256(connect_attested_slot.h256, attested_slot);
    builder.connect_biguint(&connect_attested_slot.big, &attested_slot_big);

    // connect `finalized_slot_big` and `finalized_slot`
    let connect_finalized_slot = add_virtual_biguint_hash256_connect_target(builder);
    builder.connect_hash256(connect_finalized_slot.h256, finalized_slot);
    builder.connect_biguint(&connect_finalized_slot.big, &finalized_slot_big);

    // connect `participation_big` and `participation`
    let connect_participation = add_virtual_biguint_hash256_connect_target(builder);
    builder.connect_hash256(connect_participation.h256, participation);
    builder.connect_biguint(&connect_participation.big, &participation_big);

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
        cur_state,
        cur_slot,
        cur_header,
        cur_sync_committee_i,
        cur_sync_committee_ii,
        new_state,
        new_sync_committee_i,
        new_sync_committee_ii,
        participation,
        cur_slot_big,
        attested_slot_big,
        new_sync_committee_ii_branch,
        finalized_slot_big,
        participation_big,
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

pub fn set_sync_committee_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    attested_slot: u64,
    cur_slot: u64,
    cur_sync_committee_i: &[u8; 32],
    cur_sync_committee_ii: &[u8; 32],
    sync_committee_for_attested_slot: &[u8; 32],
    sync_committee_target: CurSyncCommitteeTarget,
) {
    let cur_slot_big = BigUint::from_u64(cur_slot).unwrap();
    let attested_slot_big = BigUint::from_u64(attested_slot).unwrap();

    witness.set_biguint_target(&sync_committee_target.attested_slot_big, &attested_slot_big);
    witness.set_biguint_target(
        &sync_committee_target.cur_slot_big,
        &cur_slot_big,
    );
    witness.set_hash256_target(
        &sync_committee_target.cur_sync_committee_i,
        &cur_sync_committee_i,
    );
    witness.set_hash256_target(
        &sync_committee_target.cur_sync_committee_ii,
        &cur_sync_committee_ii,
    );
    witness.set_hash256_target(
        &sync_committee_target.sync_committee_for_attested_slot,
        &sync_committee_for_attested_slot,
    );
}

// TODO: add param docs here
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
    cur_state: &[u8; 32],
    new_state: &[u8; 32],
    cur_header: &[u8; 32],
    cur_slot: u64,
    cur_sync_committee_i: &[u8; 32],
    cur_sync_committee_ii: &[u8; 32],
    new_sync_committee_i: &[u8; 32],
    new_sync_committee_ii: &[u8; 32],
    participation: u64,
    new_sync_committee_ii_branch: &[[u8; 32]; SYNC_COMMITTEE_HEIGHT],
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

    let mut cur_slot_bytes = [0u8; 32];
    cur_slot_bytes[0..8].copy_from_slice(&cur_slot.to_le_bytes());
    witness.set_hash256_target(&target.cur_slot, &cur_slot_bytes);

    witness.set_hash256_target(&target.cur_state, &cur_state);
    witness.set_hash256_target(&target.cur_header, &cur_header);
    witness.set_hash256_target(
        &target.cur_sync_committee_i,
        &cur_sync_committee_i,
    );
    witness.set_hash256_target(
        &target.cur_sync_committee_ii,
        &cur_sync_committee_ii,
    );
    witness.set_hash256_target(&target.new_state, &new_state);
    witness.set_hash256_target(
        &target.new_sync_committee_i,
        &new_sync_committee_i,
    );
    witness.set_hash256_target(
        &target.new_sync_committee_ii,
        &new_sync_committee_ii,
    );

    let mut participation_bytes = [0u8; 32];
    participation_bytes[0..8].copy_from_slice(&participation.to_le_bytes());
    witness.set_hash256_target(&target.participation, &participation_bytes);

    let attested_slot_big_value = BigUint::from_u64(attested_slot).unwrap();
    let cur_slot_big_value = BigUint::from_u64(cur_slot).unwrap();
    witness.set_biguint_target(&target.cur_slot_big, &cur_slot_big_value);
    witness.set_biguint_target(&target.attested_slot_big, &attested_slot_big_value);

    (0..SYNC_COMMITTEE_HEIGHT).for_each(|i| {
        witness.set_hash256_target(
            &target.new_sync_committee_ii_branch[i],
            &new_sync_committee_ii_branch[i],
        )
    });

    let finalized_slot_big_value = BigUint::from_u64(finalized_slot).unwrap();
    witness.set_biguint_target(&target.finalized_slot_big, &finalized_slot_big_value);

    let participation_big_value = BigUint::from_u64(participation).unwrap();
    witness.set_biguint_target(&target.participation_big, &participation_big_value);
}
