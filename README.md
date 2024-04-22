# Dynamic SHA256 Verification Noir 
Dynamic arrays (slices) are expensive to use when computing SHA256 hashes within Noir.<br>
By using recursive proofs and field encoding, we can design a circuit where the verification cost of a preimage for a given SHA256 hash remains constant, regardless of the preimage's length, up to a specified maximum.
For example,
with a fixed byte length of ~32k it costs ~430k gates to verify, with the num of gates and thus proving time increasing for larger byte lengths.


### Circuit Generation and Demo 

1. Generate sub-circuit verification keys and hashes<br>
    ```python scripts/generate_circuits.py <chunk_num>```

2. Create hash list<br>
    ```python scripts/create_hash_list.py > ./example/src/hash_list.nr```

3. Create recursive proofs and test verification<br>
    ```python scripts/full_demo.py```

