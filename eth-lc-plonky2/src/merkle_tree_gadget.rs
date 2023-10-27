use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::hash::{
    sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
    CircuitBuilderHash, Hash256Target, WitnessHash,
};

pub struct MerkleTreeSha256Target {
    pub root: Hash256Target,
    pub leaves: Vec<Hash256Target>,
}

pub struct VerifyMerkleProofTarget {
    pub leaf: Hash256Target,
    pub proof: Vec<Hash256Target>,
    pub root: Hash256Target,
}

pub struct VerifyMerkleProofConditionalTarget {
    pub leaf: Hash256Target,
    pub proof: Vec<Hash256Target>,
    pub root: Hash256Target,
    pub v: BoolTarget, // whether to verify or not
}

pub fn compute_next_layer<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    layer_size: usize,
    prev_layer: &Vec<Hash256Target>,
) -> Vec<Hash256Target> {
    (0..layer_size)
        .map(|i| {
            let left = prev_layer[i * 2];
            let right = prev_layer[i * 2 + 1];
            builder.two_to_one_sha256(left, right)
        })
        .collect()
}

pub fn add_virtual_merkle_tree_sha256_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    height: usize,
) -> MerkleTreeSha256Target {
    let num_leaves = 1usize << height;
    let leaves: Vec<Hash256Target> = (0..num_leaves)
        .map(|_| builder.add_virtual_hash256_target())
        .collect();

    let mut layer: Vec<Hash256Target> = leaves.clone();

    for i in 1..height {
        layer = compute_next_layer(builder, 1 << (height - i), &layer);
    }
    assert_eq!(layer.len(), 2, "Error buiding merkle tree");
    let root = builder.two_to_one_sha256(layer[0], layer[1]);
    MerkleTreeSha256Target { root, leaves }
}

pub fn add_verify_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_index: usize,
    height: usize,
) -> VerifyMerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let mut proof: Vec<Hash256Target> = Vec::new();
    let leaf = builder.add_virtual_hash256_target();

    let mut curr_index = leaf_index.clone();
    let mut next_hash = leaf;

    for i in 0..height {
        proof.push(builder.add_virtual_hash256_target());

        if curr_index % 2 == 0 {
            next_hash = builder.two_to_one_sha256(next_hash, proof[i]);
        } else {
            next_hash = builder.two_to_one_sha256(proof[i], next_hash);
        }
        curr_index = curr_index / 2;
    }

    builder.connect_hash256(next_hash, root);

    VerifyMerkleProofTarget { leaf, proof, root }
}

pub fn add_verify_merkle_proof_conditional_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_index: usize,
    height: usize,
) -> VerifyMerkleProofConditionalTarget {
    let root = builder.add_virtual_hash256_target();
    let mut proof: Vec<Hash256Target> = Vec::new();
    let leaf = builder.add_virtual_hash256_target();
    let next_hash_v = builder.add_virtual_hash256_target();
    let root_v = builder.add_virtual_hash256_target();
    let v = builder.add_virtual_bool_target_safe();

    let mut curr_index = leaf_index.clone();
    let mut next_hash = leaf;

    for i in 0..height {
        proof.push(builder.add_virtual_hash256_target());

        if curr_index % 2 == 0 {
            next_hash = builder.two_to_one_sha256(next_hash, proof[i]);
        } else {
            next_hash = builder.two_to_one_sha256(proof[i], next_hash);
        }
        curr_index = curr_index / 2;
    }

    (0..8).for_each(|i| {
        let temp1 = builder.mul(v.target, next_hash[i].0);
        let temp2 = builder.mul(v.target, root[i].0);
        builder.connect(next_hash_v[i].0, temp1);
        builder.connect(root_v[i].0, temp2);
    });

    builder.connect_hash256(next_hash_v, root_v);

    VerifyMerkleProofConditionalTarget {
        leaf,
        proof,
        root,
        v,
    }
}

pub fn set_verify_merkle_proof_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    leaf: &[u8; 32],
    proof: &Vec<[u8; 32]>,
    root: &[u8; 32],
    target: &VerifyMerkleProofTarget,
) {
    assert_eq!(
        proof.len(),
        target.proof.len(),
        "Incorrect number of proof elements"
    );

    witness.set_hash256_target(&target.leaf, leaf);
    for (i, proof_elm) in target.proof.iter().enumerate() {
        witness.set_hash256_target(proof_elm, &proof[i]);
    }
    witness.set_hash256_target(&target.root, root);
}

pub fn set_partial_merkle_tree_sha256_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    leaves: &Vec<[u8; 32]>,
    target: &MerkleTreeSha256Target,
) {
    assert_eq!(
        leaves.len(),
        target.leaves.len(),
        "Not correct number of leaf values provided"
    );
    for (i, leaf) in target.leaves.iter().enumerate() {
        witness.set_hash256_target(leaf, &leaves[i]);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::hash::{CircuitBuilderHash, WitnessHash};

    use crate::merkle_tree_gadget::{
        add_virtual_merkle_tree_sha256_target, set_partial_merkle_tree_sha256_target,
    };

    #[test]
    fn test_merkle_root_2_leaves() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_tree_target = add_virtual_merkle_tree_sha256_target(&mut builder, 1);
        let expected_root = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root, merkle_tree_target.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let leaves = vec![[0u8; 32]; 2];
        let root = [
            245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61,
            35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75,
        ];
        set_partial_merkle_tree_sha256_target(&mut pw, &leaves, &merkle_tree_target);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_merkle_root_4_leaves() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_tree_target = add_virtual_merkle_tree_sha256_target(&mut builder, 2);
        let expected_root = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root, merkle_tree_target.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let leaves = vec![[0u8; 32]; 4];
        let root = [
            219, 86, 17, 78, 0, 253, 212, 193, 248, 92, 137, 43, 243, 90, 201, 168, 146, 137, 170,
            236, 177, 235, 208, 169, 108, 222, 96, 106, 116, 139, 93, 113,
        ];
        set_partial_merkle_tree_sha256_target(&mut pw, &leaves, &merkle_tree_target);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_merkle_root_8_leaves() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_tree_target = add_virtual_merkle_tree_sha256_target(&mut builder, 3);
        let expected_root = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root, merkle_tree_target.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let leaves = vec![[0u8; 32]; 8];
        let root = [
            199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66,
            237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60,
        ];
        set_partial_merkle_tree_sha256_target(&mut pw, &leaves, &merkle_tree_target);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_merkle_root_16_leaves() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_tree_target = add_virtual_merkle_tree_sha256_target(&mut builder, 4);
        let expected_root = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root, merkle_tree_target.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let leaves = vec![[0u8; 32]; 16];
        let root = [
            83, 109, 152, 131, 127, 45, 209, 101, 165, 93, 94, 234, 233, 20, 133, 149, 68, 114,
            213, 111, 36, 109, 242, 86, 191, 60, 174, 25, 53, 42, 18, 60,
        ];
        set_partial_merkle_tree_sha256_target(&mut pw, &leaves, &merkle_tree_target);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
