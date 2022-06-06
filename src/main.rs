mod divide_conquer;
mod private_intersections;
mod private_logic;
mod private_unions;

use crate::divide_conquer::divide_and_conquer_or;
use crate::private_intersections::{mpsi_large, mpsi_small};
use crate::private_logic::{mpa, mpco, mpo, mpo_unoptimized, Assistant, Leader};
use crate::private_unions::{mpsu_large, mpsu_small};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::seq::index::sample;
use rand::Rng;
use sets_multisets::sets::{gen_sets_with_intersection, gen_sets_with_union, Set};
use std::cmp;
use std::os::unix::net::UnixStream;
use std::time::Instant;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "EC-based MPSO",
    about = "Fast Multi-party Private Set Operations using Secure Elliptic Curve-based ANDs and ORs"
)]
enum Opt {
    #[structopt(about = "Performs a batch OR")]
    MultipleOrs {
        n_parties: usize,
        elements: usize,
        ones: usize,
        #[structopt(default_value = "1")]
        divisions: usize,
        #[structopt(short, long)]
        print_result: bool,
        #[structopt(short, long)]
        timings: bool,
    },
    #[structopt(about = "Perform a batch OR using a previously-proposed unoptimized protocol")]
    UnoptimizedOrs {
        n_parties: usize,
        elements: usize,
        ones: usize,
        #[structopt(short, long)]
        print_result: bool,
        #[structopt(short, long)]
        timings: bool,
    },
    #[structopt(about = "Performs a set intersection using bitsets")]
    ExactSetIntersection {
        n_parties: usize,
        set_size_k: usize,
        universe: usize,
        #[structopt(short, long)]
        print_result: bool,
    },
    #[structopt(about = "Performs a set intersection using Bloom filters")]
    ApproxSetIntersection {
        n_parties: usize,
        set_size_k: usize,
        universe: usize,
        bin_count_m: usize,
        hash_count_h: usize,
        #[structopt(short, long)]
        print_result: bool,
    },
    #[structopt(
        about = "Performs a set union using bitsets, and potentially divides-and-conquers"
    )]
    ExactSetUnion {
        n_parties: usize,
        set_size_k: usize,
        universe: usize,
        #[structopt(default_value = "1")]
        divisions: usize,
        #[structopt(short, long)]
        print_result: bool,
    },
    #[structopt(about = "Run a set of test cases")]
    Test,
}

pub fn setup(party_count: usize) -> (Leader, Vec<Assistant>) {
    let secret_keys: Vec<Scalar> = (0..party_count)
        .map(|_| Scalar::random(&mut OsRng))
        .collect();
    let partial_keys: Vec<CompressedRistretto> = secret_keys
        .iter()
        .map(|sk| (sk * &RISTRETTO_BASEPOINT_TABLE).compress())
        .collect();

    let public_key = partial_keys
        .iter()
        .map(|bk| bk.decompress().unwrap())
        .sum::<RistrettoPoint>();
    let precomputed_pk = RistrettoBasepointTable::create(&public_key);

    let quarter = Scalar::from(4u8).invert();
    let mut quartered_secret_keys = vec![secret_keys[0]];
    for sk in secret_keys.iter().take(party_count).skip(1) {
        quartered_secret_keys.push(quarter * sk)
    }

    let mut leader_streams: Vec<UnixStream> = vec![];
    let mut assistant_streams: Vec<UnixStream> = vec![];
    for _ in 1..party_count {
        let (leader_stream, assistant_stream) = UnixStream::pair().unwrap();
        leader_streams.push(leader_stream);
        assistant_streams.push(assistant_stream);
    }

    (
        Leader {
            streams: leader_streams,
            secret_key: quartered_secret_keys[0],
            public_key: precomputed_pk.clone(),
        },
        assistant_streams
            .drain(..)
            .zip(quartered_secret_keys.drain(1..))
            .map(|(stream, sk)| Assistant {
                stream,
                secret_key: sk,
                public_key: precomputed_pk.clone(),
            })
            .collect(),
    )
}

pub fn setup_unoptimized(party_count: usize) -> (Leader, Vec<Assistant>) {
    let mut secret_keys: Vec<Scalar> = (0..party_count)
        .map(|_| Scalar::random(&mut OsRng))
        .collect();
    let partial_keys: Vec<CompressedRistretto> = secret_keys
        .iter()
        .map(|sk| (sk * &RISTRETTO_BASEPOINT_TABLE).compress())
        .collect();

    let public_key = partial_keys
        .iter()
        .map(|bk| bk.decompress().unwrap())
        .sum::<RistrettoPoint>();
    let precomputed_pk = RistrettoBasepointTable::create(&public_key);

    let mut leader_streams: Vec<UnixStream> = vec![];
    let mut assistant_streams: Vec<UnixStream> = vec![];
    for _ in 1..party_count {
        let (leader_stream, assistant_stream) = UnixStream::pair().unwrap();
        leader_streams.push(leader_stream);
        assistant_streams.push(assistant_stream);
    }

    (
        Leader {
            streams: leader_streams,
            secret_key: secret_keys[0],
            public_key: precomputed_pk.clone(),
        },
        assistant_streams
            .drain(..)
            .zip(secret_keys.drain(1..))
            .map(|(stream, sk)| Assistant {
                stream,
                secret_key: sk,
                public_key: precomputed_pk.clone(),
            })
            .collect(),
    )
}

fn main() {
    let opt = Opt::from_args();

    match opt {
        Opt::MultipleOrs {
            n_parties,
            elements,
            ones,
            divisions,
            print_result,
            timings,
        } => run_multiple_ors(n_parties, elements, ones, divisions, print_result, timings),
        Opt::UnoptimizedOrs {
            n_parties,
            elements,
            ones,
            print_result,
            timings,
        } => run_unoptimized_ors(n_parties, elements, ones, print_result, timings),
        Opt::ExactSetIntersection {
            n_parties,
            set_size_k,
            universe,
            print_result,
        } => run_exact_set_intersection(n_parties, set_size_k, universe, print_result),
        Opt::ApproxSetIntersection {
            n_parties,
            set_size_k,
            universe,
            bin_count_m,
            hash_count_h,
            print_result,
        } => run_approx_set_intersection(
            n_parties,
            set_size_k,
            universe,
            bin_count_m,
            hash_count_h,
            print_result,
        ),
        Opt::ExactSetUnion {
            n_parties,
            set_size_k,
            universe,
            divisions,
            print_result,
        } => run_exact_set_union(n_parties, set_size_k, universe, divisions, print_result),

        Opt::Test => test_cases(),
    }
}

fn run_multiple_ors(
    n_parties: usize,
    elements: usize,
    ones: usize,
    divisions: usize,
    print_result: bool,
    timings: bool,
) {
    println!(
        "Performing a logical OR between {} parties with {} bits.",
        n_parties, elements
    );
    let party_bits: Vec<Vec<bool>> = (0..n_parties)
        .map(|_| {
            let one_indices = sample(&mut OsRng, elements, ones);
            let mut bits = vec![false; elements];
            for index in one_indices {
                bits[index] = true;
            }
            bits
        })
        .collect();
    let (leader, assistants) = setup(n_parties);
    let now = Instant::now();
    let result = match divisions {
        0 | 1 => mpo(leader, assistants, party_bits, timings),
        _ => divide_and_conquer_or(leader, assistants, party_bits, divisions),
    };
    println!("Took: {} ms", now.elapsed().as_millis());
    if print_result {
        println!("Result: {:?}", result);
    }
}

fn run_unoptimized_ors(
    n_parties: usize,
    elements: usize,
    ones: usize,
    print_result: bool,
    timings: bool,
) {
    println!(
        "Performing a logical OR [using the UNOPTIMIZED protocol] between {} parties with {} bits.",
        n_parties, elements
    );
    let party_bits: Vec<Vec<bool>> = (0..n_parties)
        .map(|_| {
            let one_indices = sample(&mut OsRng, elements, ones);
            let mut bits = vec![false; elements];
            for index in one_indices {
                bits[index] = true;
            }
            bits
        })
        .collect();
    let (leader, assistants) = setup_unoptimized(n_parties);
    let now = Instant::now();
    let result = mpo_unoptimized(leader, assistants, party_bits, timings);
    println!("Took: {} ms", now.elapsed().as_millis());
    if print_result {
        println!("Result: {:?}", result);
    }
}

fn run_exact_set_intersection(
    n_parties: usize,
    set_size_k: usize,
    universe: usize,
    print_result: bool,
) {
    println!(
        "Performing a set intersection between {} parties with {} elements.",
        n_parties, set_size_k
    );
    let party_sets = gen_sets_with_intersection(
        n_parties,
        set_size_k,
        universe,
        OsRng.gen_range(
            cmp::max(
                1,
                (n_parties * set_size_k) as isize - (universe * (n_parties - 1)) as isize,
            ) as usize..=set_size_k,
        ),
    );
    let (leader, assistants) = setup(n_parties);
    let now = Instant::now();
    let result = mpsi_small(leader, assistants, party_sets, universe);
    println!("Took: {} ms", now.elapsed().as_millis());
    if print_result {
        println!("Result: {:?}", result);
    }
}

fn run_approx_set_intersection(
    n_parties: usize,
    set_size_k: usize,
    universe: usize,
    bin_count_m: usize,
    hash_count_h: usize,
    print_result: bool,
) {
    println!(
        "Performing a set intersection between {} parties with {} elements.",
        n_parties, set_size_k
    );
    let party_sets = gen_sets_with_intersection(
        n_parties,
        set_size_k,
        universe,
        OsRng.gen_range(
            cmp::max(
                1,
                (n_parties * set_size_k) as isize - (universe * (n_parties - 1)) as isize,
            ) as usize..=set_size_k,
        ),
    );
    let (leader, assistants) = setup(n_parties);
    let now = Instant::now();
    let result = mpsi_large(leader, assistants, party_sets, bin_count_m, hash_count_h);
    println!("Took: {} ms", now.elapsed().as_millis());
    if print_result {
        println!("Result: {:?}", result);
    }
}

fn run_exact_set_union(
    n_parties: usize,
    set_size_k: usize,
    universe: usize,
    divisions: usize,
    print_result: bool,
) {
    println!(
        "Performing a set union between {} parties with {} elements.",
        n_parties, set_size_k
    );
    let party_sets = gen_sets_with_union(
        n_parties,
        set_size_k,
        universe,
        OsRng.gen_range(set_size_k..=cmp::min(n_parties * set_size_k, universe)),
    );
    let (leader, assistants) = setup(n_parties);
    let now = Instant::now();
    let result = match divisions {
        0 | 1 => mpsu_small(leader, assistants, party_sets, universe),
        _ => mpsu_large(leader, assistants, party_sets, universe, divisions),
    };
    println!("Took: {} ms", now.elapsed().as_millis());
    if print_result {
        println!("Result: {:?}", result);
    }
}

fn test_cases() {
    let (leader, assistants) = setup(3);
    let result = mpo(
        leader,
        assistants,
        vec![
            vec![true, false, false],
            vec![false, false, false],
            vec![false, true, false],
        ],
        false,
    );
    println!("{:?}", result);

    //let setup = Setup::new_local(3);
    println!("Simple OR");
    let (leader, assistants) = setup(3);
    let result = mpo(
        leader,
        assistants,
        vec![
            vec![false, true, false],
            vec![false, false, false],
            vec![true, false, false],
        ],
        false,
    );
    println!("{:?}", result);

    println!("Simple OR [unoptimized]");
    let (leader, assistants) = setup_unoptimized(3);
    let result = mpo_unoptimized(
        leader,
        assistants,
        vec![
            vec![false, true, false],
            vec![false, false, false],
            vec![true, false, false],
        ],
        false,
    );
    println!("{:?}", result);

    println!("Simple AND");
    let (leader, assistants) = setup(3);
    let result = mpa(
        leader,
        assistants,
        vec![
            vec![false, true, true],
            vec![false, true, false],
            vec![true, true, false],
        ],
    );
    println!("{:?}", result);

    println!("Composed OR as simple OR");
    let (leader, assistants) = setup(3);
    let result = mpco(
        leader,
        assistants,
        vec![vec![0], vec![1], vec![2]],
        vec![vec![false, false, false], vec![true, true, false]],
    );
    println!("{:?}", result);

    println!("Composed OR, [1] [0 OR 2]");
    let (leader, assistants) = setup(3);
    let result = mpco(
        leader,
        assistants,
        vec![vec![1], vec![0, 2]],
        vec![
            vec![false, true, false],
            vec![false, false, false],
            vec![true, true, false],
        ],
    );
    println!("{:?}", result);

    println!("Composed OR, [2] [2]");
    let (leader, assistants) = setup(3);
    let result = mpco(
        leader,
        assistants,
        vec![vec![2], vec![2]],
        vec![
            vec![false, true, false],
            vec![false, false, false],
            vec![true, true, false],
        ],
    );
    println!("{:?}", result);

    println!("Small union");
    let (leader, assistants) = setup(3);
    let result = mpsu_small(
        leader,
        assistants,
        vec![
            Set::new(&[1, 2, 4]),
            Set::new(&[5, 2, 1]),
            Set::new(&[0, 4, 1]),
        ],
        10,
    );
    println!("{:?}", result);

    println!("Small intersection");
    let (leader, assistants) = setup(3);
    let result = mpsi_small(
        leader,
        assistants,
        vec![
            Set::new(&[1, 2, 4]),
            Set::new(&[5, 2, 1]),
            Set::new(&[0, 4, 1, 2]),
        ],
        10,
    );
    println!("{:?}", result);

    println!("Large intersection");
    let (leader, assistants) = setup(3);
    let result = mpsi_large(
        leader,
        assistants,
        vec![
            Set::new(&[1, 2, 4]),
            Set::new(&[5, 2, 1]),
            Set::new(&[0, 4, 1, 2]),
        ],
        50,
        3,
    );
    println!("{:?}", result);

    println!("Large union");
    let (leader, assistants) = setup(3);
    let result = mpsu_large(
        leader,
        assistants,
        vec![
            Set::new(&[1003, 2, 4]),
            Set::new(&[5, 200, 1]),
            Set::new(&[0, 4, 1, 200]),
        ],
        1_000_000,
        1000,
    );
    println!("{:?}", result);
}
