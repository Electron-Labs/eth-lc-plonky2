use plonky2::{hash::hash_types::RichField, field::extension::Extendable, plonk::circuit_builder::CircuitBuilder};
use plonky2_crypto::hash::{Hash256Target, CircuitBuilderHash, sha256::{CircuitBuilderHashSha2, WitnessHashSha2}, WitnessHash};

pub struct MerkleTreeSha256Target {
    pub root: Hash256Target,
    pub internal_nodes: Vec<Hash256Target>,
    pub leaves: Vec<Hash256Target>,
}

pub fn compute_next_layer<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    layer_size: usize,
    prev_layer: &Vec<Hash256Target>,
) -> Vec<Hash256Target> {
    (0..layer_size)
        .map(|i| {
            let left = prev_layer[i*2];
            let right = prev_layer[i*2+1];
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
    let mut internal_nodes = vec![];
    let mut index = 0;
    for i in (1..height).rev() {
        let layer;
        if i == height-1 {
            layer = compute_next_layer(builder, 1<<i, &leaves);
        } else {
            layer = compute_next_layer(builder, 1<<i, &internal_nodes[index..].into());
            index += 1<<(i+1);
        }
        internal_nodes.extend(layer.into_iter());
    }
    internal_nodes = internal_nodes.into_iter().rev().collect();
    assert_eq!(internal_nodes.len(), (1usize<<height)-2);
    let root = if height == 1 {
        builder.two_to_one_sha256(leaves[0], leaves[1])
    } else {
        builder.two_to_one_sha256(internal_nodes[0], internal_nodes[1])
    };
    MerkleTreeSha256Target {
        root,
        internal_nodes,
        leaves,
    }
}

pub fn set_partial_merkle_tree_sha256_target<F: RichField, W: WitnessHashSha2<F>>(
    witness: &mut W,
    leaves: &Vec<[u8; 32]>,
    target: &MerkleTreeSha256Target,
) {
    assert_eq!(leaves.len(), target.leaves.len(), "Not correct number of leaf values provided");
    for (i, leaf) in target.leaves.iter().enumerate() {
        witness.set_hash256_target(leaf, &leaves[i]);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{plonk::{config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_data::CircuitConfig, circuit_builder::CircuitBuilder}, iop::witness::PartialWitness};
    use plonky2_crypto::hash::{CircuitBuilderHash, WitnessHash};

    use crate::merkle_tree_gadget::{add_virtual_merkle_tree_sha256_target, set_partial_merkle_tree_sha256_target};

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
        let root = [245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75];
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
        let root = [219, 86, 17, 78, 0, 253, 212, 193, 248, 92, 137, 43, 243, 90, 201, 168, 146, 137, 170, 236, 177, 235, 208, 169, 108, 222, 96, 106, 116, 139, 93, 113];
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
        let root = [199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60];
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
        let root = [83, 109, 152, 131, 127, 45, 209, 101, 165, 93, 94, 234, 233, 20, 133, 149, 68, 114, 213, 111, 36, 109, 242, 86, 191, 60, 174, 25, 53, 42, 18, 60];
        set_partial_merkle_tree_sha256_target(&mut pw, &leaves, &merkle_tree_target);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
