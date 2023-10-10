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

//use risc0_core::field::Elem;

use crate::{
    core::log2_ceil,
    hal::{Buffer, Hal},
    prove::merkle::MerkleTreeProver,
    INV_RATE, QUERIES,
};

/// A PolyGroup represents a group of polynomials, all of the same maximum
/// degree, as well as the evaluation of those polynomials over some domain that
/// is larger than that degree by some invRate. Additionally, it includes a
/// dense Merkle tree, where each entry is a single point of the domain, and the
/// leaf hash is a simple linear hash of all of the values at that point.  That
/// is, if we have 100 polynomials evaluated on 2^16 points, the merkle tree has
/// 2^16 entries, each being a hash of 100 values.  The size of the domain is
/// always a power of 2 so that we can use NTTs.
///
/// The primary purpose of the PolyGroup is for use in the DEEP-ALI protocol,
/// which basically needs 4 methods during proof generation, specifically we
/// need to: 1) Resolve queries (i.e. make MerkleColProofs)
/// 2) Do evaluation of the polynomials at 'randomly' chosen points
/// 3) Mix the polynomials via a random set of linear coefficients
/// 4) Access the raw values in the evaluation domain to 'evaluate' the
/// constraint polynomial
///
/// The poly group holds 3 buffers:
/// 1) The per-polynomial coefficients, used for evaluation + mixing
/// 2) The points evaluated on the domain in question (for the 'col' part of
/// merkle proofs) 3) The Merkle tree itself.
///
/// PolyGroups are constructed from two basic sources: steps of a computations,
/// and a single higher degree polynomial that has been split into lower degree
/// parts.  In the case of computations, the resulting steps must be padded
/// (possibly with randomized data), which is presumed to be done by the caller.
/// The constructor additionally 'shifts' the polynomial so that f(x) -> f(3*x),
/// which means that the normal NTT evaluation domain does not reveal anything
/// about the original datapoints (i.e. is zero knowledge) so long as the number
/// of queries is less than the randomized padding.
pub struct PolyGroup<H: Hal> {
    pub coeffs_vec: Vec<H::Buffer<H::Elem>>,
    //We may need a vector of counts
    pub count: usize,
    pub evaluated_vec: Vec<H::Buffer<H::Elem>>,
    pub merkle: MerkleTreeProver<H>,
}

impl<H: Hal> PolyGroup<H> {
    #[tracing::instrument(name = "PolyGroup", skip_all, fields(name = _name))]
    pub fn new(
        hal: &H,
        coeffs_vec: Vec<H::Buffer<H::Elem>>,
        count: usize,
        size: usize,
        _name: &'static str,
    ) -> Self {
        assert_eq!(coeffs_vec[0].size(), count * size);
        let domain = size * INV_RATE;
        let n: usize = coeffs_vec.len();

        let evaluated_vec: Vec<<H as Hal>::Buffer<<H as Hal>::Elem>> = (0..n)
            .map(|_i| hal.alloc_elem("evaluated", count * domain))
            .collect();
        for (evaluated, coeffs) in evaluated_vec.iter().zip(coeffs_vec.iter()) {
            hal.batch_expand_into_evaluate_ntt(&evaluated, &coeffs, count, log2_ceil(INV_RATE));
            hal.batch_bit_reverse(&coeffs, count);
        }
        //Here we combine all the evaluations into one evaluated_matrix and construct the merkle tree from it
        //This may not be the best approach but modifying the MerkleTreeProver struct is even worse
        let evaluated_matrix = evaluated_vec.iter().fold(vec![], |acc, evaluated| {
            let mut p = Vec::new();
            evaluated.view(|evaluated| p = [acc, evaluated.to_vec()].concat());
            p
        });
        let e_v = hal.copy_from_elem("name", evaluated_matrix.as_slice());
        let merkle = MerkleTreeProver::new(hal, &e_v, domain, count * n, QUERIES);
        PolyGroup {
            coeffs_vec,
            count,
            evaluated_vec,
            merkle,
        }
    }
}
