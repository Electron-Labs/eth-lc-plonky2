# Contract State
1. curr_sync_committee_hash
2. next_sync_committee_hash
3. finalised_header_root
4. execution_state_root
5. finalised_header_slot

# Sync committee remains sames // testnet
# Circuit Public Inputs:
1. curr_sync_committee_hash
2. finalised_header_root
3. execution_state_root
4. finalised_header_slot

# Circuit private inputs:
1. Light Client Finality Update(LCFU) (https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate)
2. curr_sync_committee pub keys (later)

# Circuit verification logic:
1. compute_signing_root() and verify bls sigs
2. is_valid_light_client_header (done with LCFU)
3. merkle root verification of finality branch

# Sync committee updates // testnet
# Circuit Public Inputs:
1. curr_sync_committee_hash
2. next_sync_committee_hash
3. new_sync_committee_hash
2. finalised_header_root
3. execution_state_root
4. finalised_header_slot

# Circuit private inputs:
1. Light Client Finality Update(LCFU) (https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate)
2. curr_sync_committee pub keys (later)

# Circuit verification logic:
1. compute_signing_root() and verify bls sigs
2. is_valid_light_client_header (done with LCFU)
3. merkle root verification of finality branch
4. sync committee branch merkle verification
5. new_sync_committee_sha == pub_input(new_sync_committee_sha)