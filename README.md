# Eth LightClient Plonky2

# Table of contents
1. [Run](#run)
2. [Introduction](#introduction)
3. [Smart Contract](#smart-contract)
4. [Contract state](#contract-state)
5. [Circuit](#circuit)

## Run/Test
- `cargo run --release`
- `cargo test --release`

Note: To run the program, you need to set the path of *plonky2_proof*, *plonky2_verifier_data*, *plonky2_common_data* generated from the [starky_bls12_381](https://github.com/Electron-labs/starky_bls12_381/tree/feat/ec_aggregate_pk) repo.

## Introduction
This circuit (accompanied by a smart contract) aims to create proof of Ethereum Blockchain's consensus on its finalized header.
It can be used to generate proofs for 2 scenarios:
- When the lightclient update is from the same period as the `slot` on the smart contract.
- When the lightclient update is from the next period

## Smart Contract
The contract maintains 3 state variables as follows:
1. `slot`: Finalized beacon slot on ethereum
2. `header`: Beacon block header root at slot `slot`
3. `cur_state`: It is the Merkle root of several relevant <b>trusted</b> details for the beacon block at slot `slot`. This is explained in the next section.

All these variables are updated by an external function call `function lightclientUpdate`, which will execute only if the provided proof gets verified.

## Contract state
The contract state is the Merkle root of a tree having the following 4 leaves, corresponding to a certain lightclient update. Note: the suffixes *_i* and *_ii* represent 2 consecutive periods.
- `slot`: Slot number
- `header`: Beacon block header root
- `sync_committee_i`: Sync committee ssz corresponding to the period of `slot`
- `sync_committee_ii`: Sync committee ssz for the next period

## Circuit
It has 3 public inputs:
1. `cur_state`: Current state of the contract
2. `new_state`: New contract state - the one that is intended to replace the existing one on-chain in the contract.

and various private inputs w.r.t. the lightclient update under consideration.

The circuit can be broken down into the following key subcircuits:
- #### VerifySignatures
  <p>The BLS signature verification for the <i>Signing Root</i> happens here. This verifies the correctness of the <i>Signing Root</i>. The public keys used for this purpose are ensured to be correct by looking them up in the `cur_state`.
- #### SigningRoot
  <p>Next, we establish the correctness of the <i>Attested Header Root</i>. It is done by recomputing the <i>Signing Root</i> using the <i>Attested Header Root</i>. The <i>Attested Header Root</i> must be correct for the correct recomputation.</p>
- #### MerkleTree (Attested Header)
  <p><i>Attested Header Root</i> is computed in this circuit using a number of inputs(leafs) including <i>Attested State Root</i> and <i> Attested Slot</i>. This ensures the correctness of all the inputs used.</p>
  #### VerifyMerkleProof (Finalized Header)
  <p>Here, the <i>Finality Branch</i> (from the LC update) is used to prove <i>Finalized Header Root</i> against <i>Attested State Root</i>.</p>
- #### MerkleTree (Finalized Header)
  <p><i>Finalized Header Root</i> is computed in this circuit using a number of inputs(leafs) including <i> Finalized Slot</i> and <i>Finalized State Root</i>. This ensures the correctness of all the inputs used.</p>
- #### SyncCommitteeSSZ
  It computes the SSZ root of the *sync_committee* structure, which should match either one of *curr_sync_committee_i* and *next_sync_committee_i*. 
- #### VerifySyncCommittee
  <p>It verifies `new_sync_committee_ii` using the merkle proof against <i>Finalized State Root</i>, and  `new_sync_committee_i` by appropriately looking it up into the `cur_state`.</p>
- #### UpdateValidityTarget
  - Ensures the Finalized Slot is atleast Cur Slot.
  - Ensures enough participants.
- #### ContractStateTarget
  <p>It is used to construct the <i>Contract State</i> Merkle tree.
- #### Plonky2 proof verifier
  It verifies a plonky2 proof which is a recursive proof of verification of BLS signatures (using starky and plonky2).

- Several other helper circuits are also used throughout.

## Performance

The plonky2 circuit has ~2.98M constraints. Proof generation takes ~300s for generating a proof on AWS r6a.8xlarge machine.
