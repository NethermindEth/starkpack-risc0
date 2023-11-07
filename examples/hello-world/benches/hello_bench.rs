use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use hello_world::multiply;
use hello_world_methods::MULTIPLY_ID;

const MAX_NUM_TRACES: usize = 50;
pub fn prove_factors(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove prime factors");
    for num_traces in 1..=MAX_NUM_TRACES {
        let pairs_to_multiply: Vec<(u64, u64)> = vec![(11, 17); num_traces];
        group.bench_function(BenchmarkId::from_parameter(num_traces), |bench| {
            bench.iter(|| multiply(pairs_to_multiply.clone()));
        });
    }
}

pub fn verify_factors(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify prime factors");
    for num_traces in 1..=MAX_NUM_TRACES {
        let pairs_to_multiply: Vec<(u64, u64)> = vec![(11, 17); num_traces];
        let (receipt, _) = multiply(pairs_to_multiply);
        group.bench_function(BenchmarkId::from_parameter(num_traces), |bench| {
            bench.iter(|| {
                receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
                );
            });
        });
    }
}

criterion_group!(benches, prove_factors, verify_factors);
criterion_main!(benches);
