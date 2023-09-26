use plonky2::{hash::hash_types::RichField, field::extension::Extendable, plonk::circuit_builder::CircuitBuilder};
use plonky2_crypto::hash::{Hash256Target, CircuitBuilderHash, sha256::{CircuitBuilderHashSha2, WitnessHashSha2}, WitnessHash};

pub struct MerkleTreeSha256Gadget {
    pub root: Hash256Target,
    pub internal_nodes: Vec<Hash256Target>,
    pub leaves: Vec<Hash256Target>,
    pub height: usize,
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

impl MerkleTreeSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let num_leaves = 1usize << height;
        let leaves: Vec<Hash256Target> = (0..num_leaves)
            .map(|_| builder.add_virtual_hash256_target())
            .collect();
        let mut internal_nodes = Vec::with_capacity((1usize << height) - 2);
        let mut prev_layer = leaves.clone();
        for i in (1..height).rev() {
            prev_layer = compute_next_layer(builder, i, &prev_layer);
            internal_nodes[1<<(i-1)..1<<i].copy_from_slice(&prev_layer);
        }
        let root = builder.two_to_one_sha256(prev_layer[0], prev_layer[1]);
        Self {
            root,
            internal_nodes,
            leaves,
            height,
        }
    }

    pub fn set_partial_witness<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        leaves: &Vec<[u8; 32]>,
    ) {
        assert_eq!(leaves.len(), self.leaves.len(), "Not enough number of leaf values provided");
        for (i, leaf) in self.leaves.iter().enumerate() {
            witness.set_hash256_target(leaf, &leaves[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{plonk::{config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_data::CircuitConfig, circuit_builder::CircuitBuilder}, iop::witness::PartialWitness};
    use plonky2_crypto::hash::{CircuitBuilderHash, WitnessHash};

    use crate::merkle_tree_gadget::MerkleTreeSha256Gadget;

    #[test]
    fn test_merkle_root() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_tree_gadget = MerkleTreeSha256Gadget::add_virtual_to(&mut builder, 1);
        let expected_root = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root, merkle_tree_gadget.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let leaves = vec![[0u8; 32], [0u8; 32]];
        let root = [245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75];
        merkle_tree_gadget.set_partial_witness(&mut pw, &leaves);
        pw.set_hash256_target(&expected_root, &root);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}
