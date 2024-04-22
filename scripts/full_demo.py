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
import tempfile
import subprocess

def split_hex_into_31_byte_chunks(hexstr):
    return ["0x" + hexstr[i:i+62] for i in range(0, len(hexstr), 62)]

def pad_list(input_list, target_length, pad_item):
    return input_list + [pad_item] * (target_length - len(input_list))

def hex_string_to_byte_array(hex_string: str) -> list[int]:
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    byte_array = []
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i : i + 2], 16))
    return byte_array


def validate_bytelen(bytelen: int, max_bytes: int):
    if bytelen > 32000 or bytelen < 1:
        raise Exception("Invalid bytelength")


def get_chunk_file_name(chunk_id: int):
    return f"vkey_chunk_{chunk_id:04d}.json"


def normalize_hex_str(hex_str: str) -> str:
    mod_str = hex_str
    if hex_str.startswith("0x"):
        mod_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        mod_str = f"0{mod_str}"
    return mod_str


async def initialize_build_folder(
    circuit_fs: dict, name: str
) -> tempfile.TemporaryDirectory:
    temp_dir = tempfile.TemporaryDirectory()
    command = f"nargo init --bin --name {name}"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=temp_dir.name,
    )

    stdout, stderr = await process.communicate()
    if stderr:
        raise Exception(stderr.decode())

    for file_path, file_content in circuit_fs.items():
        file_full_path = os.path.join(temp_dir.name, file_path)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        async with aiofiles.open(file_full_path, "w+") as file:
            await file.write(file_content)

    return temp_dir


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
    
    return await initialize_build_folder(SHA_CIRCUIT_FS, NAME)


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
    return await initialize_build_folder(EXAMPLE_CIRCUIT_FS, NAME)


async def compile_project(compilation_dir: str):
    command = "nargo compile --only-acir"
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise Exception(stderr.decode())


async def create_witness(output: str, compilation_dir: str):
    async with aiofiles.open(
        os.path.join(compilation_dir, "Prover.toml"), "w+"
    ) as file:
        await file.write(output)

    command = "nargo execute witness"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        raise Exception(stderr.decode())


async def create_sha256_witness(normalized_hex_str: str, compilation_dir: str):
    data_hash = hashlib.sha256(bytes.fromhex(normalized_hex_str)).hexdigest()
    encoded_data = pad_list(split_hex_into_31_byte_chunks(normalized_hex_str), 1033, "0x00")
    expected_hash_encoded = split_hex_into_31_byte_chunks(data_hash)

    output = f"encoded_data={json.dumps(encoded_data)}\nexpected_hash_encoded={json.dumps(expected_hash_encoded)}"
    # print(output)
    await create_witness(output, compilation_dir)


async def build_raw_verification_key(vk_file: str, bb_binary: str, compilation_dir: str):
    command = f"{bb_binary} write_vk -o {vk_file}"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(stderr.decode())

async def extract_vk_as_fields(vk_file: str, bb_binary: str, compilation_dir: str):
    command = f"{bb_binary} vk_as_fields -k {vk_file} -o -"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(stderr.decode())
    return json.loads(stdout)


"""

struct Sha256VerificationProof {
    verification_key : [Field; 114],
    proof : [Field; 93],
    public_inputs : [Field; 32],
	key_hash_index: u32
}
fn main(
	proof_data: Sha256VerificationProof
)
"""


async def create_demo_proof_witness(sha_proof_components: dict, build_folder: str):
    #f"verification_key=[{','.join([x for x in sha_proof_components['verification_key']])}]",
    output = "\n".join(
        [
            f"verification_key={json.dumps(sha_proof_components['verification_key'])}",
            f"proof={json.dumps(sha_proof_components['proof'])}",
            f"public_inputs={json.dumps(sha_proof_components['public_inputs'])}",
            f"key_hash_index={sha_proof_components['key_hash_index']}",
        ]
    )
    # print(output)
    await create_witness(output, build_folder)


async def verify_proof(bb_binary: str, compilation_dir: str, vk_path: str):
    command = f"{bb_binary} verify -p ./target/proof -k {vk_path}"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(stderr.decode())

async def create_proof(bb_binary: str, compilation_dir: str, vk_path: str, pub_inputs: int):
    command = f"{bb_binary} prove -o ./target/proof"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(stderr.decode())

    command = f"{bb_binary} proof_as_fields -p ./target/proof -k {vk_path} -o -"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise Exception(stderr.decode())
    proof_output = json.loads(stdout)
    return proof_output[:pub_inputs], proof_output[pub_inputs:]


async def extract_cached_vkey_data(
    bytelen: int, chunk_file: str
) -> tuple[str, list[str], str]:
    async with aiofiles.open(chunk_file, "r") as file:
        blob = json.loads(await file.read())[str(bytelen)]
        return (blob['vk_as_fields'][0], blob['vk_as_fields'][1:], blob['vk_bytes'])


async def build_sha256_proof_and_input(
    data_hex_str: str,
    chunk_folder: str = "generated_circuit_data/",
    bb_binary: str = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary",
    max_bytes: int = 32000,
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
    print("done")
    build_folder = await initialize_sha256_build_folder(bytelen)

    vk_file = "public_input_proxy_vk"
    async with aiofiles.open(
        os.path.join(build_folder.name, vk_file), "wb+"
    ) as f:
        await f.write(bytes.fromhex(vk_hexstr_bytes))

    print("Compiling inner sha circuit...")
    await compile_project(build_folder.name)
    print("done")
    await create_sha256_witness(data, build_folder.name)
    print("Creating inner sha proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(
        bb_binary, build_folder.name, vk_file, int.from_bytes(bytes.fromhex(normalize_hex_str(vkey_as_fields[4])), "big")
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
    await build_raw_verification_key(vkey_fn, bb_binary, build_folder.name)
    vk_fields = await extract_vk_as_fields(vkey_fn, bb_binary, build_folder.name)
    print("done")
    print("Creating final recursive proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(
        bb_binary, build_folder.name, vkey_fn, int.from_bytes(bytes.fromhex(normalize_hex_str(vk_fields[7])), "big")
    )
    print("done")
    print("Verifying final proof...")
    await verify_proof(bb_binary, build_folder.name, vkey_fn)

# TESTS


async def test_proof_gen():
    inner_proof_data = await build_sha256_proof_and_input("01"*1000)
    await build_and_verify_simple_demo_proof(inner_proof_data)
    print("Built and verified recursive proof!")

if __name__ == "__main__":
    asyncio.run(test_proof_gen())

