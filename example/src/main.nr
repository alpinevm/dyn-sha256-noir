use dep::std;
mod hash_list;
 
fn main(
    verification_key : [Field; 114],
    proof : [Field; 93],
    public_inputs : [Field; 1035],
	key_hash_index: u32
) {
    std::verify_proof(
        verification_key.as_slice(),
        proof.as_slice(),
        public_inputs.as_slice(),
        hash_list::CIRCUIT_HASH_LIST[key_hash_index]
    );
}
