import asyncio
import math
import hashlib
import time
import multiprocessing
import sys
import psutil
from typing import Any
import aiofiles
import json
import os
from noir_lib import (
    initialize_noir_project_folder,
    compile_project,
    create_witness,
    normalize_hex_str,
    pad_list,
    hex_string_to_byte_array,
    split_hex_into_31_byte_chunks,
    create_proof,
    build_raw_verification_key,
    extract_vk_as_fields,
    verify_proof
)


def validate_bytelen(bytelen: int, max_bytes: int):
    if bytelen > 32000 or bytelen < 1:
        raise Exception("Invalid bytelength")


def get_chunk_file_name(chunk_id: int):
    return f"vkey_chunk_{chunk_id:04d}.json"


async def initialize_sha256_build_folder(bytelen: int):
    NAME = "dynamic_sha_lib"
    SHA_CIRCUIT_FS = {
        "src/main.nr": """
use dep::std;

// Amount of bytes this circuit will consume from encoded_data
global BYTELEN = __PLACEHOLDER__;
// the amount of Field chunks needed to store BYTELEN amount of u8s should always be => ceil(BYTELEN/31)
global BYTELEN_CHUNK = (BYTELEN + 30) / 31;
// overflow, if bytelen mod 31 is equal to 0 then we set overflow equal to 31
global OVERFLOW = (BYTELEN % 31) + ((BYTELEN % 31 == 0) as u32 * 31);
global MAX_BYTE_CHUNKS = 1033;

#[recursive]
fn main(expected_hash_encoded: pub [Field; 2], encoded_data: pub [Field; MAX_BYTE_CHUNKS]) {
	assert(MAX_BYTE_CHUNKS >= (BYTELEN/BYTELEN_CHUNK));
	let mut data: [u8; BYTELEN] = [0; BYTELEN];
	for i in 0..BYTELEN_CHUNK-1 {
		let decoded_field = encoded_data[i].to_be_bytes(31);
		for j in 0..31 {
			data[(i*31)+j] = decoded_field[j];
		}
	}
	let decoded_field = encoded_data[BYTELEN_CHUNK-1].to_be_bytes(OVERFLOW);
	for i in 0..OVERFLOW {
		data[((BYTELEN_CHUNK-1)*31)+i] = decoded_field[i];
	}
	let expected_hash_l1: [u8] = expected_hash_encoded[0].to_be_bytes(31);
	let expected_hash_l2: [u8] = expected_hash_encoded[1].to_be_bytes(1);
	let mut expected_hash: [u8; 32] = [0; 32];
	for i in 0..31{
		expected_hash[i] = expected_hash_l1[i];	
	}
	expected_hash[31] = expected_hash_l2[0];
	assert(std::hash::sha256(data) == expected_hash);
}
""".replace("__PLACEHOLDER__", str(bytelen))
    }

    return await initialize_noir_project_folder(SHA_CIRCUIT_FS, NAME)


async def initialize_example_recursive_build_folder(
    hash_list_file: str = "example/src/hash_list.nr",
    main_file: str = "example/src/main.nr",
):
    NAME = "example"
    async with aiofiles.open(hash_list_file, "r") as f:
        hash_list_contents = await f.read()

    async with aiofiles.open(main_file, "r") as f:
        main_file_contents = await f.read()

    EXAMPLE_CIRCUIT_FS = {
        "src/hash_list.nr": hash_list_contents,
        "src/main.nr": main_file_contents,
    }
    return await initialize_noir_project_folder(EXAMPLE_CIRCUIT_FS, NAME)


async def create_sha256_witness(normalized_hex_str: str, max_chunks: int, compilation_dir: str):
    data_hash = hashlib.sha256(bytes.fromhex(normalized_hex_str)).hexdigest()
    encoded_data = pad_list(
        split_hex_into_31_byte_chunks(normalized_hex_str), max_chunks, "0x00"
    )
    expected_hash_encoded = split_hex_into_31_byte_chunks(data_hash)

    output = f"encoded_data={json.dumps(encoded_data)}\nexpected_hash_encoded={json.dumps(expected_hash_encoded)}"
    await create_witness(output, compilation_dir)

async def create_demo_proof_witness(sha_proof_components: dict, build_folder: str):
    prover_toml_string = "\n".join(
        [
            f"verification_key={json.dumps(sha_proof_components['verification_key'])}",
            f"proof={json.dumps(sha_proof_components['proof'])}",
            f"public_inputs={json.dumps(sha_proof_components['public_inputs'])}",
            f"key_hash_index={sha_proof_components['key_hash_index']}",
        ]
    )
    await create_witness(prover_toml_string, build_folder)


async def extract_cached_vkey_data(
    bytelen: int, chunk_file: str
) -> tuple[str, list[str], str]:
    async with aiofiles.open(chunk_file, "r") as file:
        blob = json.loads(await file.read())[str(bytelen)]
        return (blob["vk_as_fields"][0], blob["vk_as_fields"][1:], blob["vk_bytes"])


async def build_sha256_proof_and_input(
    data_hex_str: str,
    chunk_folder: str = "generated_circuit_data/",
    bb_binary: str = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary",
    max_bytes: int = 32000,
    max_chunks: int = 1033
) -> dict:
    data = normalize_hex_str(data_hex_str)

    bytelen = len(data) // 2

    validate_bytelen(bytelen, max_bytes)

    print("Extracting vkey data...")
    vkey_hash, vkey_as_fields, vk_hexstr_bytes = await extract_cached_vkey_data(
        bytelen,
        os.path.join(
            chunk_folder, get_chunk_file_name(math.floor((bytelen - 1) / 1000))
        ),
    )
    print("VKEY AS FIELDS")
    print(vkey_as_fields)
    print("done")
    build_folder = await initialize_sha256_build_folder(bytelen)

    vk_file = "public_input_proxy_vk"
    async with aiofiles.open(os.path.join(build_folder.name, vk_file), "wb+") as f:
        await f.write(bytes.fromhex(vk_hexstr_bytes))

    print("Compiling inner sha circuit...")
    await compile_project(build_folder.name)
    print("done")
    await create_sha256_witness(data, max_chunks, build_folder.name)
    print("Creating inner sha proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(
        vk_file,
        int.from_bytes(bytes.fromhex(normalize_hex_str(vkey_as_fields[4])), "big"),
        build_folder.name,
        bb_binary,
    )
    print("done")
    build_folder.cleanup()
    return {
        "verification_key": vkey_as_fields,
        "proof": proof_as_fields,
        "public_inputs": public_inputs_as_fields,
        "key_hash_index": bytelen - 1,
        "key_hash": vkey_hash,
    }


async def build_and_verify_simple_demo_proof(
    sha_proof_components: dict,
    bb_binary: str = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary",
):
    build_folder = await initialize_example_recursive_build_folder()
    print("Compiling demo circuit...")
    await compile_project(build_folder.name)
    print("done")
    await create_demo_proof_witness(sha_proof_components, build_folder.name)
    vkey_fn = "vk"
    print("Creating verification key for demo circuit...")
    await build_raw_verification_key(vkey_fn, build_folder.name, bb_binary)
    vk_fields = await extract_vk_as_fields(vkey_fn,  build_folder.name, bb_binary)
    print("done")
    print("Creating final recursive proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(
        vkey_fn,
        int.from_bytes(bytes.fromhex(normalize_hex_str(vk_fields[7])), "big"),
        build_folder.name,
        bb_binary,
    )
    print("done")
    print("Verifying final proof...")
    await verify_proof( vkey_fn, build_folder.name, bb_binary)


# TESTS


async def test_proof_gen():
    inner_proof_data = await build_sha256_proof_and_input("01" * 1000)
    await build_and_verify_simple_demo_proof(inner_proof_data)
    print("Built and verified recursive proof!")


if __name__ == "__main__":
    asyncio.run(test_proof_gen())
