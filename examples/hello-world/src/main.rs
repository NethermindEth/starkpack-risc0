// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{fs::File, io::Write};

use hello_world::multiply;
use hello_world_methods::MULTIPLY_ID;

fn main() {
    let pairs_to_multiply: Vec<(u64, u64)> = vec![(2, 3), (3, 4), (4, 5), (5, 6)];
    let (receipt, _) = multiply(pairs_to_multiply);

    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );

    let ser_proof = serde_json::to_string(&receipt).unwrap();
    let mut proof_file = File::create("receipt.json").unwrap();
    proof_file.write_all(ser_proof.as_bytes()).unwrap();
}
