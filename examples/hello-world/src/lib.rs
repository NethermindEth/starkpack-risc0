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

#[doc = include_str!("../README.md")]
use hello_world_methods::MULTIPLY_ELF;
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv, Receipt,
};

// This is a Hello World demo for the RISC Zero zkVM.
// By running the demo, Alice can produce a receipt that proves that she knows
// some numbers a and b, such that a*b == 391.
// The factors a and b are kept secret.

// Compute the product a*b inside the zkVM
pub fn multiply(pairs: Vec<(u64, u64)>) -> (Receipt, Vec<u64>) {
    let envs: Vec<ExecutorEnv<'_>> = pairs
        .into_iter()
        .map(|(a, b)| {
            ExecutorEnv::builder()
                .add_input(&to_vec(&a).unwrap())
                .add_input(&to_vec(&b).unwrap())
                .build()
                .unwrap()
        })
        .collect();
    // Obtain the default prover.
    let prover = default_prover();
    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(envs, MULTIPLY_ELF).unwrap();
    // Extract journal of receipt (i.e. output c, where c = a * b)
    let mut cs = Vec::new();
    for journal in &receipt.journals {
        let c: u64 = from_slice(journal).expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );

        // Report the product
        println!("I know the factors of {}, and I can prove it!", c);
        cs.push(c);
    }

    (receipt, cs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        const TEST_FACTOR_ONE: u64 = 17;
        const TEST_FACTOR_TWO: u64 = 23;
        let (_, result) = multiply(vec![(17, 23)]);
        assert_eq!(
            result,
            TEST_FACTOR_ONE * TEST_FACTOR_TWO,
            "We expect the zkVM output to be the product of the inputs"
        )
    }
}
