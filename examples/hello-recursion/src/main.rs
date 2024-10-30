// TODO: Update the name of the method loaded by the prover. E.g., if the method
// is `multiply`, replace `METHOD_NAME_ELF` with `MULTIPLY_ELF` and replace
// `METHOD_NAME_ID` with `MULTIPLY_ID`
use hello_recursion_methods::{RECURSION_TOY_ELF, RECURSION_TOY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

fn main() {
    // First, we construct an executor environment
    let env = ExecutorEnv::builder().build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(vec![env], RECURSION_TOY_ELF).unwrap();

    receipt.verify(RECURSION_TOY_ID).unwrap();
}
