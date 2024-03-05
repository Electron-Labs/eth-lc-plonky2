use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    hash::{CircuitBuilderHash, Hash256Target},
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

pub fn add_virtual_is_equal_big_uint_target<F: RichField + Extendable<D>, const D: usize>(
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

// connects a `BigUintTarget` and its corresponsing `Hash256Target`
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

pub fn bits_from_hex(hex: &str) -> Vec<bool> {
    let only_hex;
    if hex.split_at(2).0 == "0x" {
        only_hex = hex.split_at(2).1;
    } else {
        only_hex = hex;
    }
    let bytes = hex::decode(only_hex).unwrap();
    bytes.iter().flat_map(|b| {
        (0..8).into_iter().map(|i| (b>>i)&1 != 0).collect::<Vec<_>>()
    }).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::utils::{
        add_virtual_biguint_hash256_connect_target, add_virtual_is_equal_big_uint_target,
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
    use plonky2_crypto::{hash::WitnessHash, nonnative::gadgets::biguint::WitnessBigUint};

    use super::bits_from_hex;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_is_equal_big_uint_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let num1 = 6594800;
        let num2 = 6594800;
        let num3 = 6594800 + 1;

        let is_equal_big_uint_target1 = add_virtual_is_equal_big_uint_target(&mut builder);
        let is_equal_big_uint_target2 = add_virtual_is_equal_big_uint_target(&mut builder);
        let mut witness = PartialWitness::new();

        let big1_value = BigUint::from_u64(num1).unwrap();
        let big2_value = BigUint::from_u64(num2).unwrap();
        let big3_value = BigUint::from_u64(num3).unwrap();
        witness.set_biguint_target(&is_equal_big_uint_target1.big1, &big1_value);
        witness.set_biguint_target(&is_equal_big_uint_target1.big2, &big2_value);

        witness.set_biguint_target(&is_equal_big_uint_target2.big1, &big2_value);
        witness.set_biguint_target(&is_equal_big_uint_target2.big2, &big3_value);

        let one_bool = builder.constant_bool(true);
        let zero_bool = builder.constant_bool(false);
        builder.connect(is_equal_big_uint_target1.result.target, one_bool.target);
        builder.connect(is_equal_big_uint_target2.result.target, zero_bool.target);

        let data = builder.build::<C>();
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_biguint_hash256_connect_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let slot: u64 = 25000;

        let biguint_hash256_connect_target =
            add_virtual_biguint_hash256_connect_target(&mut builder);
        let mut witness = PartialWitness::new();

        let mut slot_bytes = [0u8; 32];
        slot_bytes[0..8].copy_from_slice(&slot.to_le_bytes());
        witness.set_hash256_target(&biguint_hash256_connect_target.h256, &slot_bytes);

        let big_slot = BigUint::from_u64(slot).unwrap();
        witness.set_biguint_target(&biguint_hash256_connect_target.big, &big_slot);

        let data = builder.build::<C>();
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_bits_from_hex() {
        let bits = bits_from_hex("0102");
        let mut res = vec![false; 16];
        res[0] = true;
        res[9] = true;
        assert_eq!(bits, res);
    }
}
