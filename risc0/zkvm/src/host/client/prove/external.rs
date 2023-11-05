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

use std::path::{Path, PathBuf};

use anyhow::Result;
use risc0_binfmt::MemoryImage;

use super::{Prover, ProverOpts};
use crate::{ApiClient, ExecutorEnv, Receipt, VerifierContext};

/// An implementation of a [Prover] that runs proof workloads via an external
/// `r0vm` process.
pub struct ExternalProver {
    name: String,
    r0vm_path: PathBuf,
}

impl ExternalProver {
    /// Construct an [ExternalProver].
    pub fn new<P: AsRef<Path>>(name: &str, r0vm_path: P) -> Self {
        Self {
            name: name.to_string(),
            r0vm_path: r0vm_path.as_ref().to_path_buf(),
        }
    }
}

impl Prover for ExternalProver {
    fn prove(
        &self,
        envs: Vec<ExecutorEnv<'_>>,
        ctx: &VerifierContext,
        opts: &ProverOpts,
        image: MemoryImage,
    ) -> Result<Receipt> {
        log::debug!("Launching {}", &self.r0vm_path.to_string_lossy());
        let env = envs.first().map(|env| env.to_owned()).unwrap();

        let image_id = image.compute_id();
        let client = ApiClient::new_sub_process(&self.r0vm_path)?;
        println!("in host client prove");
        let receipt = client.prove(&env, opts.clone(), image.try_into()?)?;
        receipt.verify_with_context(ctx, image_id)?;

        Ok(receipt)
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }
}
