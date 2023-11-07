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
use anyhow::Result;
use risc0_circuit_rv32im::{
    layout::{OutBuffer, LAYOUT},
    REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA,
};
use risc0_core::field::baby_bear::{BabyBear, Elem, ExtElem};
use risc0_zkp::{
    adapter::TapsProvider,
    hal::{CircuitHal, Hal},
    layout::Buffer,
};
use std::time::Instant;

use super::{HalPair, ProverServer};
use crate::{
    host::{receipt::SegmentReceipts, server::packer::PackSession, CIRCUIT},
    InnerReceipt, Receipt, Segment, SegmentReceipt, VerifierContext,
};

/// An implementation of a Prover that runs locally.
pub struct ProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>,
    C: CircuitHal<H>,
{
    name: String,
    hal_pair: HalPair<H, C>,
}

impl<H, C> ProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>,
    C: CircuitHal<H>,
{
    /// Construct a [ProverImpl] with the given name and [HalPair].
    pub fn new(name: &str, hal_pair: HalPair<H, C>) -> Self {
        Self {
            name: name.to_string(),
            hal_pair,
        }
    }
}

impl<H, C> ProverServer for ProverImpl<H, C>
where
    H: Hal<Field = BabyBear, Elem = Elem, ExtElem = ExtElem>,
    C: CircuitHal<H>,
{
    fn prove_session(&self, ctx: &VerifierContext, pack_session: PackSession) -> Result<Receipt> {
        /* Here we start changing the code to introduce StarkPack */
        log::info!("prove_session: {}", self.name);
        let pack_segments = pack_session.resolve_packed_segments()?;
        let _num_traces = pack_segments.len();
        let mut segments = Vec::new();

        for pack_segment in pack_segments.iter() {
            segments.push(
                self.prove_segment(ctx, pack_segment.iter().map(|segment| segment).collect())?,
            );
        }
        // explicitly avoid hooks
        // for (i, segment_ref) in session0.segments.iter().enumerate() {
        //     let segment_vec = sessions
        //         .iter()
        //         .map(|&session| session.segments[i].resolve())
        //         .collect();
        //     for hook in &session0.hooks {
        //         hook.on_pre_prove_segment(&pack_session.joined_segments.first());
        //     }
        //     segments.push(self.prove_segment(ctx, &pack_session.resolve_packed_segments())?);
        //     for hook in &session0.hooks {
        //         hook.on_post_prove_segment(&segment_vec[0]);
        //     }
        // }
        let inner = InnerReceipt::Flat(SegmentReceipts(segments));
        //we will need to modify the journal as we have pub data of multiple traces
        let receipt = Receipt::new(inner, pack_session.pack_journals[0].clone());
        Ok(receipt)
    }

    fn prove_segment(
        &self,
        ctx: &VerifierContext,
        segments: Vec<&Segment>,
    ) -> Result<SegmentReceipt> {
        let seg_index = segments[0].index;
        let _ = ctx;
        log::info!(
            "prove_segment[{}]: po2: {}, insn_cycles: {}",
            segments[0].index,
            segments[0].po2,
            segments[0].insn_cycles,
        );
        let _time = Instant::now();
        let (hal, circuit_hal) = (self.hal_pair.hal.as_ref(), &self.hal_pair.circuit_hal);
        let hashfn = &hal.get_hash_suite().name;

        let mut executors = PackSession::generate_machine_executors(segments);
        let mut adapters = PackSession::generate_adapters(&mut executors)?;

        let mut prover: risc0_zkp::prove::Prover<'_, H> =
            risc0_zkp::prove::Prover::new(hal, CIRCUIT.get_taps());
        let num_traces = adapters.len();
        adapters[0].execute_first(prover.iop());
        prover.set_po2(adapters[0].po2() as usize);
        for i in 1..num_traces {
            adapters[i].execute(prover.iop());
        }
        let code_vec = adapters
            .iter()
            .map(|adapter| hal.copy_from_elem("code", &adapter.get_code().as_slice()))
            .collect();
        let data_vec = adapters
            .iter()
            .map(|adapter| hal.copy_from_elem("data", &adapter.get_data().as_slice()))
            .collect();
        prover.commit_group(REGISTER_GROUP_CODE, code_vec);
        prover.commit_group(REGISTER_GROUP_DATA, data_vec);

        for adapter in adapters.iter_mut() {
            adapter.accumulate(prover.iop());
        }
        let accum_vec = adapters
            .iter()
            .map(|adapter| hal.copy_from_elem("accum", &adapter.get_accum().as_slice()))
            .collect();
        prover.commit_group(REGISTER_GROUP_ACCUM, accum_vec);

        // Creating three vectors is very not ideal, we should use Another type to represent this
        let mut globals_vec = Vec::new();
        for adapter in adapters.iter() {
            let globals = [
                hal.copy_from_elem("mix", &adapter.get_mix().as_slice()),
                hal.copy_from_elem("out", &adapter.get_io().as_slice()),
            ];
            globals_vec.push(globals.to_vec());
        }
        let mut globals_vec_ref = Vec::new();
        for globals in globals_vec.iter() {
            let global_ref: Vec<_> = globals.iter().map(|global| global).collect();
            globals_vec_ref.push(global_ref)
        }
        let mut globals_vec_ref_ref = Vec::new();
        for globals in globals_vec_ref.iter() {
            globals_vec_ref_ref.push(globals.as_slice())
        }

        let out_slice_vec: Vec<_> = adapters
            .iter()
            .map(|adapter| adapter.get_io().as_slice())
            .collect();

        log::debug!("Globals: {:?}", OutBuffer(&out_slice_vec[0]).tree(&LAYOUT));
        let mut seal = prover.finalize(globals_vec_ref_ref, circuit_hal.as_ref());
        seal.push(num_traces as u32);
        let receipt = SegmentReceipt {
            seal,
            index: seg_index,
            hashfn: hashfn.clone(),
        };
        Ok(receipt)
    }

    fn get_peak_memory_usage(&self) -> usize {
        self.hal_pair.hal.get_memory_usage()
    }
}
