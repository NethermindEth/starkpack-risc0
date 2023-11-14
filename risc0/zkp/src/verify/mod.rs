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

//! Cryptographic algorithms for verifying a ZK proof of compute

mod fri;
mod merkle;
mod read_iop;

use alloc::{vec, vec::Vec};
use core::{cell::RefCell, fmt, iter::zip};

pub(crate) use merkle::MerkleTreeVerifier;
pub use read_iop::ReadIOP;
use risc0_core::field::{Elem, ExtElem, Field, RootsOfUnity};

use crate::{
    adapter::{CircuitCoreDef, REGISTER_GROUP_ACCUM, REGISTER_GROUP_CODE, REGISTER_GROUP_DATA},
    core::{digest::Digest, hash::HashSuite, log2_ceil},
    taps::TapSet,
    INV_RATE, MAX_CYCLES_PO2, QUERIES,
};

#[derive(PartialEq)]
pub enum VerificationError {
    ReceiptFormatError,
    ControlVerificationError,
    ImageVerificationError,
    MerkleQueryOutOfRange { idx: usize, rows: usize },
    InvalidProof,
    JournalDigestMismatch,
    UnexpectedExitCode,
    InvalidHashSuite,
}

impl fmt::Debug for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerificationError::ReceiptFormatError => write!(f, "invalid receipt format"),
            VerificationError::ControlVerificationError => write!(f, "control_id mismatch"),
            VerificationError::ImageVerificationError => write!(f, "image_id mismatch"),
            VerificationError::MerkleQueryOutOfRange { idx, rows } => write!(
                f,
                "Requested Merkle validation on row {idx}, but only {rows} rows exist",
            ),
            VerificationError::InvalidProof => write!(f, "Verification indicates proof is invalid"),
            VerificationError::JournalDigestMismatch => {
                write!(f, "Journal digest mismatch detected")
            }
            VerificationError::UnexpectedExitCode => write!(f, "Unexpected exit_code"),
            VerificationError::InvalidHashSuite => write!(f, "Invalid hash suite"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}

trait VerifyParams<F: Field> {
    const CHECK_SIZE: usize = INV_RATE * F::ExtElem::EXT_SIZE;
}

struct TapCache<F: Field> {
    taps: *const TapSet<'static>,
    mix: F::ExtElem,
    tap_mix_pows: Vec<F::ExtElem>,
    check_mix_pows: Vec<F::ExtElem>,
}

pub(crate) struct Verifier<'a, F, C>
where
    F: Field,
{
    circuit: &'a C,
    suite: &'a HashSuite<F>,
    po2: u32,
    steps: usize,
    out_vec: Vec<Option<&'a [F::Elem]>>,
    mix_vec: Vec<Vec<F::Elem>>,
    tap_cache: RefCell<Option<TapCache<F>>>,
}

impl<'a, F: Field, C> VerifyParams<F> for Verifier<'a, F, C> {}

impl<'a, F, C> Verifier<'a, F, C>
where
    F: Field,
    C: CircuitCoreDef<F>,
{
    fn new(circuit: &'a C, suite: &'a HashSuite<F>) -> Self {
        Self {
            circuit,
            suite,
            po2: 0,
            steps: 0,
            out_vec: vec![],
            mix_vec: vec![],
            tap_cache: RefCell::new(None),
        }
    }

    // Compute the FRI verify taps sum.
    #[allow(clippy::too_many_arguments)]
    fn fri_eval_taps(
        &self,
        num_traces: usize,
        taps: &TapSet<'static>,
        mix: F::ExtElem,
        combo_u: &[F::ExtElem],
        check_row: &[F::Elem],
        back_one: F::Elem,
        x: F::Elem,
        z: F::ExtElem,
        rows: [&[F::Elem]; 3],
    ) -> F::ExtElem {
        let mut tot = vec![F::ExtElem::ZERO; num_traces * taps.combos_size() + 1];
        let combo_count = taps.combos_size();
        let x = F::ExtElem::from_subfield(&x);
        let mut tap_cache = self.tap_cache.borrow_mut();
        if let Some(ref c) = &mut *tap_cache {
            if c.taps != taps || c.mix != mix {
                // log::debug!("Resetting tap cache");
                tap_cache.take();
            }
        }
        if tap_cache.is_none() {
            let mut cur_mix = F::ExtElem::ONE;
            let mut tap_mix_pows = Vec::with_capacity(num_traces * taps.reg_count());
            for _ in 0..num_traces {
                for _reg in taps.regs() {
                    tap_mix_pows.push(cur_mix);
                    cur_mix *= mix;
                }
            }
            assert_eq!(
                tap_mix_pows.len(),
                num_traces * taps.reg_count(),
                "Miscalculated capacity for tap_mix_pows"
            );
            let mut check_mix_pows = Vec::with_capacity(Self::CHECK_SIZE);
            for _ in 0..Self::CHECK_SIZE {
                check_mix_pows.push(cur_mix);
                cur_mix *= mix;
            }
            tap_cache.replace(TapCache {
                taps,
                mix,
                tap_mix_pows,
                check_mix_pows,
            });
        }
        let tap_cache = tap_cache.as_ref().unwrap();
        let taps_size = tap_cache.tap_mix_pows.len() / num_traces;
        for index in 0..num_traces {
            let _this_tap_mix = &tap_cache.tap_mix_pows[index * taps_size..(index + 1) * taps_size];
            // for (i, (reg, cur)) in zip(taps.regs(), tap_cache.tap_mix_pows.iter()).enumerate() {
            for (reg, cur) in zip(taps.regs(), _this_tap_mix) {
                tot[index * combo_count + reg.combo_id()] +=
                //This may not be the reg.size() this may be the taps.group_size(reg.group())
                *cur * rows[reg.group()][index * taps.group_size(reg.group()) + reg.offset()];
            }
        }
        for (i, cur) in zip(0..Self::CHECK_SIZE, tap_cache.check_mix_pows.iter()) {
            tot[num_traces * combo_count] += *cur * check_row[i];
        }
        let mut ret = F::ExtElem::ZERO;
        for index in 0..num_traces {
            for i in 0..combo_count {
                let begin_trace = index * taps.tot_combo_backs;
                let num = tot[index * combo_count + i]
                    - self.poly_eval(
                        &combo_u[begin_trace + (taps.combo_begin[i] as usize)
                            ..begin_trace + (taps.combo_begin[i + 1] as usize)],
                        x,
                    );
                let mut divisor = F::ExtElem::ONE;
                for back in taps.get_combo(i).slice() {
                    divisor *= x - z * back_one.pow(*back as usize);
                }
                ret += num * divisor.inv();
            }
        }
        let check_num = tot[num_traces * combo_count] - combo_u[num_traces * taps.tot_combo_backs];
        let check_div = x - z.pow(INV_RATE);
        ret += check_num * check_div.inv();
        ret
    }

    fn verify<CheckCodeFn>(
        &mut self,
        seal: &'a [u32],
        check_code: CheckCodeFn,
    ) -> Result<(), VerificationError>
    where
        CheckCodeFn: Fn(u32, &Digest) -> Result<(), VerificationError>,
    {
        if seal.is_empty() {
            return Err(VerificationError::ReceiptFormatError);
        }
        let (&num_traces, seal) = seal.split_last().unwrap();
        let num_traces = num_traces as usize;

        let taps = self.circuit.get_taps();
        let hashfn = self.suite.hashfn.as_ref();

        // Make IOP
        let mut iop = ReadIOP::new(seal, self.suite.rng.as_ref());

        // Read any execution state
        self.execute(num_traces, &mut iop);
        // Get the size
        assert!(self.po2 as usize <= MAX_CYCLES_PO2);
        let size = 1 << self.po2;
        let domain = INV_RATE * size;
        // log::debug!("size = {size}, po2 = {po2}");

        // Get taps and compute sizes
        let code_size = taps.group_size(REGISTER_GROUP_CODE);
        let data_size = taps.group_size(REGISTER_GROUP_DATA);
        let accum_size = taps.group_size(REGISTER_GROUP_ACCUM);

        // Get merkle root for the code merkle tree.
        // The code merkle tree contains the control instructions for the zkVM.
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("code_merkle");
        let code_merkle =
            MerkleTreeVerifier::new(&mut iop, hashfn, domain, num_traces * code_size, QUERIES);
        // log::debug!("codeRoot = {}", code_merkle.root());
        //check_code(self.po2, code_merkle.root())?;
        let _ = check_code;

        // Get merkle root for the data merkle tree.
        // The data merkle tree contains the execution trace of the program being run,
        // including memory accesses as well as the permutation of those memory
        // accesses sorted by location used by PLONK.
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("data_merkle");
        let data_merkle =
            MerkleTreeVerifier::new(&mut iop, hashfn, domain, num_traces * data_size, QUERIES);
        // log::debug!("dataRoot = {}", data_merkle.root());

        // Prep accumulation
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("accumulate");
        // Fill in accum mix
        for _ in 0..num_traces {
            self.mix_vec
                .push((0..C::MIX_SIZE).map(|_| iop.random_elem()).collect());
        }
        // Get merkle root for the accum merkle tree.
        // The accum merkle tree contains the accumulations for two permutation check
        // arguments: Each permutation check consists of a pre-permutation
        // accumulation and a post-permutation accumulation.
        // The first permutation check uses memory-based values (see PLONK paper for
        // details). This permutation is used to re-order memory accesses for
        // quicker verification. The second permutation check uses bytes-based
        // values (see PLOOKUP paper for details). This permutation is used to
        // implement a look-up table.
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("accum_merkle");
        let accum_merkle =
            MerkleTreeVerifier::new(&mut iop, hashfn, domain, num_traces * accum_size, QUERIES);
        // log::debug!("accumRoot = {}", accum_merkle.root());

        // Get a pseudorandom value with which to mix the constraint polynomials.
        // See DEEP-ALI protocol from DEEP-FRI paper for details on constraint mixing.
        let poly_mix_vec: Vec<<F as Field>::ExtElem> =
            (0..num_traces).map(|_| iop.random_ext_elem()).collect();
        let final_mix = iop.random_elem(); //F::Elem::ONE;
        println!("verifeir mix {:?}", final_mix);
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("check_merkle");
        let check_merkle: MerkleTreeVerifier<'_> =
            MerkleTreeVerifier::new(&mut iop, hashfn, domain, Self::CHECK_SIZE, QUERIES);
        // log::debug!("checkRoot = {}", check_merkle.root());

        // Get a pseudorandom DEEP query point
        // See DEEP-ALI protocol from DEEP-FRI paper for details on DEEP query.
        let z = iop.random_ext_elem();
        // log::debug!("Z = {z:?}");
        let back_one = F::Elem::ROU_REV[self.po2 as usize];

        // Read the U coeffs (the interpolations of the taps) + commit their hash.
        let num_taps: usize = taps.tap_size();
        let coeff_u = iop.read_field_elem_slice(num_traces * num_taps + Self::CHECK_SIZE);
        let hash_u = self.suite.hashfn.hash_ext_elem_slice(coeff_u);
        iop.commit(&hash_u);
        // Now, convert U polynomials from coefficient form to evaluation form
        let mut cur_pos = 0;
        let mut eval_u = Vec::with_capacity(num_traces * num_taps);
        for _ in 0..num_traces {
            for reg in taps.regs() {
                for i in 0..reg.size() {
                    let x = z * back_one.pow(reg.back(i));
                    let fx = self.poly_eval(&coeff_u[cur_pos..(cur_pos + reg.size())], x);
                    eval_u.push(fx);
                }
                cur_pos += reg.size();
            }
        }

        assert_eq!(
            eval_u.len(),
            num_traces * num_taps,
            "Miscalculated capacity for eval_us"
        );

        // Compute the core constraint polynomial.
        // I.e. the set of all constraints mixed by poly_mix
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("> compute_polynomial");
        // let result = self.compute_polynomial(&eval_u, poly_mix);
        let mut result_vec: Vec<<F as Field>::ExtElem> = Vec::new();
        for index in 0..num_traces {
            result_vec.push(
                self.circuit
                    .poly_ext(
                        &poly_mix_vec[index],
                        &eval_u[index * num_taps..(index + 1) * num_taps],
                        &[self.out_vec[index].unwrap(), &self.mix_vec[index]],
                    )
                    .tot,
            )
        }
        #[cfg(not(target_os = "zkvm"))]
        log::debug!("< compute_polynomial");
        // log::debug!("Result = {result:?}");

        // Now generate the check polynomial
        // TODO: This currently treats the extension degree as hardcoded at 4, with
        // the structure of the code and the value of `remap` (and how it is
        // accessed) only working in the extension degree = 4 case.
        // However, for generic fields the extension degree may be different
        // TODO: Therefore just using the to/from baby bear shims for now

        //Not sure if this works
        let mut check = F::ExtElem::default();
        let remap = [0, 2, 1, 3];
        let fp0 = F::Elem::ZERO;
        let fp1 = F::Elem::ONE;
        for (i, rmi) in remap.iter().enumerate() {
            check += coeff_u[num_traces * num_taps + rmi]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp1, fp0, fp0, fp0]);
            check += coeff_u[num_traces * num_taps + rmi + 4]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp1, fp0, fp0]);
            check += coeff_u[num_traces * num_taps + rmi + 8]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp0, fp1, fp0]);
            check += coeff_u[num_traces * num_taps + rmi + 12]
                * z.pow(i)
                * F::ExtElem::from_subelems([fp0, fp0, fp0, fp1]);
        }
        let three = F::Elem::from_u64(3);
        check *= (F::ExtElem::from_subfield(&three) * z).pow(size) - F::ExtElem::ONE;
        // log::debug!("Check = {check:?}");
        let mut final_result = F::ExtElem::default();
        for index in 0..num_traces {
            final_result += result_vec[index] * final_mix.pow(index);
        }
        if check != final_result {
            println!("final_poly {:?}", final_result);
            println!("check {:?}", check);
            return Err(VerificationError::InvalidProof);
        }
        // Set the mix mix value, pseudorandom value used for FRI batching
        let mix = iop.random_ext_elem();
        // log::debug!("mix = {mix:?}");

        // Make the mixed U polynomials.
        // combo_u has one element for each column with the same set of taps.
        // These columns share a denominator in the DEEP-ALI equation.
        // We group these terms together to reduce the number of inverses we
        // need to compute.
        let mut combo_u: Vec<F::ExtElem> =
            vec![F::ExtElem::ZERO; num_traces * taps.tot_combo_backs + 1];
        // println!("combo verifer {:?}", combo_u.len());
        let mut cur_mix = F::ExtElem::ONE;
        cur_pos = 0;
        let mut tap_mix_pows = Vec::with_capacity(num_traces * taps.reg_count());
        for index in 0..num_traces {
            for reg in taps.regs() {
                for i in 0..reg.size() {
                    // combo_u[index * (taps.combo_begin[reg.combo_id()] as usize) + i] +=
                    //     cur_mix * coeff_u[cur_pos + i];
                    combo_u[index * taps.tot_combo_backs
                        + (taps.combo_begin[reg.combo_id()] as usize)
                        + i] += cur_mix * coeff_u[cur_pos + i];
                }
                tap_mix_pows.push(cur_mix);
                cur_mix *= mix;
                cur_pos += reg.size();
            }
        }

        assert_eq!(
            tap_mix_pows.len(),
            num_traces * taps.reg_count(),
            "Miscalculated capacity for tap_mix_pows"
        );
        // log::debug!("cur_mix: {cur_mix:?}, cur_pos: {cur_pos}");
        // Handle check group
        let mut check_mix_pows = Vec::with_capacity(Self::CHECK_SIZE);
        for _ in 0..Self::CHECK_SIZE {
            combo_u[num_traces * taps.tot_combo_backs] += cur_mix * coeff_u[cur_pos];
            cur_pos += 1;
            check_mix_pows.push(cur_mix);
            cur_mix *= mix;
        }

        assert_eq!(
            check_mix_pows.len(),
            Self::CHECK_SIZE,
            "Miscalculated capacity for check_mix_pows"
        );
        // log::debug!("cur_mix: {cur_mix:?}");

        let gen = <F::Elem as RootsOfUnity>::ROU_FWD[log2_ceil(domain)];
        // log::debug!("FRI-verify, size = {size}");
        self.fri_verify(&mut iop, size, |iop, idx| {
            // log::debug!("fri_verify");
            let x = gen.pow(idx);
            let rows = [
                accum_merkle.verify(iop, hashfn, idx)?,
                code_merkle.verify(iop, hashfn, idx)?,
                data_merkle.verify(iop, hashfn, idx)?,
            ];
            let check_row = check_merkle.verify(iop, hashfn, idx)?;
            let ret = self.fri_eval_taps(
                num_traces, taps, mix, &combo_u, check_row, back_one, x, z, rows,
            );
            Ok(ret)
        })?;
        iop.verify_complete();
        Ok(())
    }

    fn execute(&mut self, num_traces: usize, iop: &mut ReadIOP<'a, F>) {
        // Read the outputs + size
        self.out_vec
            .push(Some(iop.read_field_elem_slice(C::OUTPUT_SIZE)));
        self.po2 = *iop.read_u32s(1).first().unwrap();
        self.steps = 1 << self.po2;
        for _ in 1..num_traces {
            self.out_vec
                .push(Some(iop.read_field_elem_slice(C::OUTPUT_SIZE)));
            //let _ = *iop.read_u32s(1).first().unwrap();
        }
    }

    /// Evaluate a polynomial whose coefficients are in the extension field at a
    /// point.
    fn poly_eval(&self, coeffs: &[F::ExtElem], x: F::ExtElem) -> F::ExtElem {
        let mut mul_x = F::ExtElem::ONE;
        let mut tot = F::ExtElem::ZERO;
        for coeff in coeffs {
            tot += *coeff * mul_x;
            mul_x *= x;
        }
        tot
    }
}

/// Verify a seal is valid for the given circuit, and code checking function.
#[must_use]
#[tracing::instrument(skip_all)]
pub fn verify<F, C, CheckCode>(
    circuit: &C,
    suite: &HashSuite<F>,
    seal: &[u32],
    check_code: CheckCode,
) -> Result<(), VerificationError>
where
    F: Field,
    C: CircuitCoreDef<F>,
    CheckCode: Fn(u32, &Digest) -> Result<(), VerificationError>,
{
    Verifier::<F, C>::new(circuit, suite).verify(seal, check_code)
}
