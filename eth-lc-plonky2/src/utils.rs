use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    hash::{
        CircuitBuilderHash, Hash256Target,
    },
};

pub struct IsEqualBigUint {
    pub big1: BigUintTarget,
    pub big2: BigUintTarget,
    pub result: BoolTarget,
}

pub struct BigUintHash256ConnectTarget {
    pub big: BigUintTarget,
    pub h256: Hash256Target,
}

pub fn add_is_equal_big_uint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> IsEqualBigUint {
    let big1 = builder.add_virtual_biguint_target(8);
    let big2 = builder.add_virtual_biguint_target(8);
    let mut result = builder.constant_bool(true);

    let mut is_equal_temp = builder.constant_bool(true);
    (0..8).for_each(|i| {
        is_equal_temp = builder.is_equal(big1.limbs[i].0, big2.limbs[i].0);
        result = builder.and(result, is_equal_temp);
    });

    IsEqualBigUint { big1, big2, result }
}

pub fn add_virtual_biguint_hash256_connect_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BigUintHash256ConnectTarget {
    let big = builder.add_virtual_biguint_target(8);
    let h256 = builder.add_virtual_hash256_target();

    for i in 0..8 {
        let limb_big = big.get_limb(i);
        let limb_h256 = h256[i];
        let bit_targets_big = builder.split_le_base::<2>(limb_big.0, 32);
        let bit_targets_h256 = builder.split_le_base::<2>(limb_h256.0, 32);
        (0..4).for_each(|i| {
            (0..8).for_each(|j| {
                // TODO: currently connecting at bit level, do it at byte level
                builder.connect(bit_targets_big[8 * i + j], bit_targets_h256[24 - 8 * i + j])
            })
        });
    }

    BigUintHash256ConnectTarget { big, h256 }
}
