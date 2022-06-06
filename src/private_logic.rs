use crate::OsRng;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use std::io::Write;
use std::iter::Sum;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Instant;
use subtle::{Choice, ConditionallySelectable};

pub struct Leader {
    pub streams: Vec<UnixStream>,
    pub secret_key: Scalar,
    pub public_key: RistrettoBasepointTable,
}

pub struct Assistant {
    pub stream: UnixStream,
    pub secret_key: Scalar,
    pub public_key: RistrettoBasepointTable,
}

pub fn encrypt(
    bits: &[bool],
    public_key: &RistrettoBasepointTable,
) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
    let randomness_1: Vec<Scalar> = (0..bits.len())
        .map(|_| Scalar::random(&mut OsRng))
        .collect();
    let randomness_1_prime = (0..bits.len()).map(|_| Scalar::random(&mut OsRng));

    let randomness_2 = bits
        .iter()
        .zip(&randomness_1)
        .zip(randomness_1_prime)
        .map(|((bit, a), b)| Scalar::conditional_select(a, &b, Choice::from(*bit as u8)));

    let c1s = randomness_1
        .iter()
        .map(|r| (r * &RISTRETTO_BASEPOINT_TABLE))
        .collect::<Vec<RistrettoPoint>>();
    let c2s = randomness_2
        .map(|r| (&r * public_key))
        .collect::<Vec<RistrettoPoint>>();

    (c1s, c2s)
}

pub fn encrypt_unoptimized(
    bits: &[bool],
    public_key: &RistrettoBasepointTable,
) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
    let randomness: Vec<Scalar> = (0..bits.len())
        .map(|_| Scalar::random(&mut OsRng))
        .collect();

    let c1s = randomness
        .iter()
        .map(|r| (r * &RISTRETTO_BASEPOINT_TABLE))
        .collect::<Vec<RistrettoPoint>>();
    let c2s = randomness
        .iter()
        .zip(bits)
        .map(|(r, b)| {
            (r * public_key)
                + RistrettoPoint::conditional_select(
                    &RistrettoPoint::identity(),
                    &RISTRETTO_BASEPOINT_POINT,
                    Choice::from(*b as u8),
                )
        })
        .collect::<Vec<RistrettoPoint>>();

    (c1s, c2s)
}

impl Leader {
    pub fn private_batched_or(&mut self, bits: &[bool], timings: bool) -> Vec<bool> {
        // TODO: Do not rely on bit count
        let bit_count = bits.len();

        //1. Encrypt
        let now = Instant::now();
        let cs = encrypt(bits, &self.public_key);

        // 2. Sum and randomize
        let received_ciphertexts: Vec<(Vec<CompressedRistretto>, Vec<CompressedRistretto>)> = self
            .streams
            .iter()
            .map(|stream| bincode::deserialize_from(stream).unwrap())
            .collect();
        if timings {
            println!("Encrypt and receive: {} ms", now.elapsed().as_millis());
        }

        let now = Instant::now();
        let c1s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| {
                RistrettoPoint::sum(
                    received_ciphertexts
                        .iter()
                        .map(|(c1, _)| c1[i].decompress().unwrap()),
                ) + cs.0[i]
            })
            .collect();
        let c2s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| {
                RistrettoPoint::sum(
                    received_ciphertexts
                        .iter()
                        .map(|(_, c2)| c2[i].decompress().unwrap()),
                ) + cs.1[i]
            })
            .collect();

        let factors: Vec<Scalar> = (0..bit_count).map(|_| Scalar::random(&mut OsRng)).collect();

        let c1s_multiplied: Vec<RistrettoPoint> =
            c1s_sum.iter().zip(&factors).map(|(c1, r)| r * c1).collect();
        let c1s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c1s_multiplied);
        let c2s_multiplied: Vec<RistrettoPoint> =
            c2s_sum.iter().zip(&factors).map(|(c2, r)| r * c2).collect();
        let c2s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c2s_multiplied);

        let message: Vec<u8> =
            bincode::serialize(&(c1s_multiplied_compressed, c2s_multiplied_compressed)).unwrap();
        if timings {
            println!("Leader randomization: {} ms", now.elapsed().as_millis());
        }

        self.streams.iter().for_each(|mut stream| {
            stream.write_all(&message).unwrap();
        });

        self.finish_or(timings)
    }

    pub fn private_batched_or_unoptimized(&mut self, bits: &[bool], timings: bool) -> Vec<bool> {
        // TODO: Do not rely on bit count
        let bit_count = bits.len();

        //1. Encrypt
        let now = Instant::now();
        let cs = encrypt_unoptimized(bits, &self.public_key);

        // 2. Sum and randomize
        let received_ciphertexts: Vec<(Vec<CompressedRistretto>, Vec<CompressedRistretto>)> = self
            .streams
            .iter()
            .map(|stream| bincode::deserialize_from(stream).unwrap())
            .collect();
        if timings {
            println!("Encrypt and receive: {} ms", now.elapsed().as_millis());
        }

        let now = Instant::now();
        let c1s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| {
                RistrettoPoint::sum(
                    received_ciphertexts
                        .iter()
                        .map(|(c1, _)| c1[i].decompress().unwrap()),
                ) + cs.0[i]
            })
            .collect();
        let c2s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| {
                RistrettoPoint::sum(
                    received_ciphertexts
                        .iter()
                        .map(|(_, c2)| c2[i].decompress().unwrap()),
                ) + cs.1[i]
            })
            .collect();

        let factors: Vec<Scalar> = (0..bit_count).map(|_| Scalar::random(&mut OsRng)).collect();

        let c1s_randomized: Vec<RistrettoPoint> = c1s_sum
            .iter()
            .zip(&factors)
            .map(|(c1, r)| c1 + r * &RISTRETTO_BASEPOINT_TABLE)
            .collect();
        let c1s_randomized_compressed: Vec<CompressedRistretto> =
            c1s_randomized.iter().map(|c| c.compress()).collect();
        let c2s_randomized: Vec<RistrettoPoint> = c2s_sum
            .iter()
            .zip(&factors)
            .map(|(c2, r)| c2 + r * &self.public_key)
            .collect();
        let c2s_randomized_compressed: Vec<CompressedRistretto> =
            c2s_randomized.iter().map(|c| c.compress()).collect();

        let message: Vec<u8> =
            bincode::serialize(&(c1s_randomized_compressed, c2s_randomized_compressed)).unwrap();
        if timings {
            println!("Leader randomization: {} ms", now.elapsed().as_millis());
        }

        self.streams.iter().for_each(|mut stream| {
            stream.write_all(&message).unwrap();
        });

        self.finish_or_unoptimized(timings, c1s_randomized, c2s_randomized)
    }

    pub fn finish_or(&mut self, timings: bool) -> Vec<bool> {
        // 4. Aggregation
        let now = Instant::now();
        let ciphertexts: Vec<(Vec<RistrettoPoint>, Vec<RistrettoPoint>)> = self
            .streams
            .iter()
            .map(|stream| {
                let (c1s, c2s): (Vec<CompressedRistretto>, Vec<CompressedRistretto>) =
                    bincode::deserialize_from(stream).unwrap();

                let c1s_decompressed = c1s.iter().map(|c| c.decompress().unwrap()).collect();
                let c2s_decompressed = c2s.iter().map(|c| c.decompress().unwrap()).collect();

                (c1s_decompressed, c2s_decompressed)
            })
            .collect();

        let bit_count = ciphertexts[0].0.len();

        let c1s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| RistrettoPoint::sum(ciphertexts.iter().map(|(c1, _)| c1[i])))
            .collect();
        let c2s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .map(|i| RistrettoPoint::sum(ciphertexts.iter().map(|(_, c2)| c2[i])))
            .collect();

        let message: Vec<u8> =
            bincode::serialize(&RistrettoPoint::double_and_compress_batch(&c1s_sum)).unwrap();
        if timings {
            println!(
                "Assistant randomization and aggregation: {} ms",
                now.elapsed().as_millis()
            );
        }

        self.streams.iter().for_each(|mut stream| {
            stream.write_all(&message).unwrap();
        });

        // 6. Decryption and final comparison
        let now = Instant::now();
        let c1s_partial_decryption: Vec<RistrettoPoint> =
            c1s_sum.iter().map(|c| self.secret_key * c).collect();

        let ciphertexts: Vec<Vec<RistrettoPoint>> = self
            .streams
            .iter()
            .map(|stream| {
                let cs: Vec<CompressedRistretto> = bincode::deserialize_from(stream).unwrap();

                let cs_decompressed = cs.iter().map(|c| c.decompress().unwrap()).collect();

                cs_decompressed
            })
            .collect();

        let output = c1s_partial_decryption
            .iter()
            .zip(c2s_sum)
            .enumerate()
            .map(|(i, (sigma_1, beta))| {
                (sigma_1 + RistrettoPoint::sum(ciphertexts.iter().map(|c| c[i]))) != beta
            })
            .collect();

        if timings {
            println!("Decrypt: {} ms", now.elapsed().as_millis());
        }
        output
    }

    pub fn finish_or_unoptimized(
        &mut self,
        timings: bool,
        c1s_randomized: Vec<RistrettoPoint>,
        c2s_randomized: Vec<RistrettoPoint>,
    ) -> Vec<bool> {
        // 4. Aggregation
        let now = Instant::now();
        let ciphertexts: Vec<(Vec<RistrettoPoint>, Vec<RistrettoPoint>)> = self
            .streams
            .iter()
            .map(|stream| {
                let (c1s, c2s): (Vec<CompressedRistretto>, Vec<CompressedRistretto>) =
                    bincode::deserialize_from(stream).unwrap();

                let c1s_decompressed = c1s.iter().map(|c| c.decompress().unwrap()).collect();
                let c2s_decompressed = c2s.iter().map(|c| c.decompress().unwrap()).collect();

                (c1s_decompressed, c2s_decompressed)
            })
            .collect();

        let bit_count = ciphertexts[0].0.len();

        let factors: Vec<Scalar> = (0..bit_count).map(|_| Scalar::random(&mut OsRng)).collect();

        let c1s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .zip(&factors)
            .map(|(i, r)| {
                r * c1s_randomized[i] + RistrettoPoint::sum(ciphertexts.iter().map(|(c1, _)| c1[i]))
            })
            .collect();
        let c2s_sum: Vec<RistrettoPoint> = (0..bit_count)
            .zip(&factors)
            .map(|(i, r)| {
                r * c2s_randomized[i] + RistrettoPoint::sum(ciphertexts.iter().map(|(_, c2)| c2[i]))
            })
            .collect();

        let message: Vec<u8> = bincode::serialize(
            &c1s_sum
                .iter()
                .map(|c| c.compress())
                .collect::<Vec<CompressedRistretto>>(),
        )
        .unwrap();
        if timings {
            println!(
                "Assistant randomization and aggregation: {} ms",
                now.elapsed().as_millis()
            );
        }

        self.streams.iter().for_each(|mut stream| {
            stream.write_all(&message).unwrap();
        });

        // 6. Decryption and final comparison
        let now = Instant::now();
        let c1s_partial_decryption: Vec<RistrettoPoint> =
            c1s_sum.iter().map(|c| self.secret_key * c).collect();

        let ciphertexts: Vec<Vec<RistrettoPoint>> = self
            .streams
            .iter()
            .map(|stream| {
                let cs: Vec<CompressedRistretto> = bincode::deserialize_from(stream).unwrap();

                let cs_decompressed = cs.iter().map(|c| c.decompress().unwrap()).collect();

                cs_decompressed
            })
            .collect();

        let output = c1s_partial_decryption
            .iter()
            .zip(c2s_sum)
            .enumerate()
            .map(|(i, (sigma_1, beta))| {
                !RistrettoPoint::is_identity(
                    &(sigma_1 + RistrettoPoint::sum(ciphertexts.iter().map(|c| c[i])) - beta),
                )
            })
            .collect();

        if timings {
            println!("Decrypt: {} ms", now.elapsed().as_millis());
        }
        output
    }
}

impl Assistant {
    pub fn encrypt_and_send_bits(&mut self, bits: &[bool]) {
        let cs = encrypt(bits, &self.public_key);
        let compressed_cs = (
            RistrettoPoint::double_and_compress_batch(&cs.0),
            RistrettoPoint::double_and_compress_batch(&cs.1),
        );
        let message: Vec<u8> = bincode::serialize(&compressed_cs).unwrap();
        self.stream.write_all(&message).unwrap();
    }

    pub fn encrypt_and_send_bits_unoptimized(&mut self, bits: &[bool]) {
        let cs = encrypt_unoptimized(bits, &self.public_key);
        let compressed_cs: (Vec<CompressedRistretto>, Vec<CompressedRistretto>) = (
            cs.0.iter().map(|c| c.compress()).collect(),
            cs.1.iter().map(|c| c.compress()).collect(),
        );
        let message: Vec<u8> = bincode::serialize(&compressed_cs).unwrap();
        self.stream.write_all(&message).unwrap();
    }

    pub fn private_batched_or(&mut self, bits: &[bool]) {
        // 1. Encrypt
        self.encrypt_and_send_bits(bits);

        self.finish_or();
    }

    pub fn private_batched_or_unoptimized(&mut self, bits: &[bool]) {
        // 1. Encrypt
        self.encrypt_and_send_bits_unoptimized(bits);

        self.finish_or_unoptimized();
    }

    pub fn finish_or(&mut self) {
        // 3. Randomization
        let (c1s, c2s): (Vec<CompressedRistretto>, Vec<CompressedRistretto>) =
            bincode::deserialize_from(&self.stream).unwrap();

        let bit_count = c1s.len();
        let factors: Vec<Scalar> = (0..bit_count).map(|_| Scalar::random(&mut OsRng)).collect();

        let c1s_multiplied: Vec<RistrettoPoint> = c1s
            .iter()
            .zip(&factors)
            .map(|(c1, r)| r * c1.decompress().unwrap())
            .collect();
        let c1s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c1s_multiplied);
        let c2s_multiplied: Vec<RistrettoPoint> = c2s
            .iter()
            .zip(&factors)
            .map(|(c2, r)| r * c2.decompress().unwrap())
            .collect();
        let c2s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c2s_multiplied);

        let message: Vec<u8> =
            bincode::serialize(&(c1s_multiplied_compressed, c2s_multiplied_compressed)).unwrap();

        self.stream.write_all(&message).unwrap();

        // 5. Decryption
        let cs: Vec<CompressedRistretto> = bincode::deserialize_from(&self.stream).unwrap();

        let cs_decrypted: Vec<RistrettoPoint> = cs
            .iter()
            .map(|c| self.secret_key * c.decompress().unwrap())
            .collect();
        let cs_decrypted_compressed = RistrettoPoint::double_and_compress_batch(&cs_decrypted);

        let message: Vec<u8> = bincode::serialize(&cs_decrypted_compressed).unwrap();

        self.stream.write_all(&message).unwrap();
    }

    pub fn finish_or_unoptimized(&mut self) {
        // 3. Randomization
        let (c1s, c2s): (Vec<CompressedRistretto>, Vec<CompressedRistretto>) =
            bincode::deserialize_from(&self.stream).unwrap();

        let bit_count = c1s.len();
        let factors: Vec<Scalar> = (0..bit_count).map(|_| Scalar::random(&mut OsRng)).collect();

        let c1s_multiplied: Vec<RistrettoPoint> = c1s
            .iter()
            .zip(&factors)
            .map(|(c1, r)| r * c1.decompress().unwrap())
            .collect();
        let c1s_multiplied_compressed: Vec<CompressedRistretto> =
            c1s_multiplied.iter().map(|c| c.compress()).collect();
        let c2s_multiplied: Vec<RistrettoPoint> = c2s
            .iter()
            .zip(&factors)
            .map(|(c2, r)| r * c2.decompress().unwrap())
            .collect();
        let c2s_multiplied_compressed: Vec<CompressedRistretto> =
            c2s_multiplied.iter().map(|c| c.compress()).collect();

        let message: Vec<u8> =
            bincode::serialize(&(c1s_multiplied_compressed, c2s_multiplied_compressed)).unwrap();

        self.stream.write_all(&message).unwrap();

        // 5. Decryption
        let cs: Vec<CompressedRistretto> = bincode::deserialize_from(&self.stream).unwrap();

        let cs_decrypted: Vec<RistrettoPoint> = cs
            .iter()
            .map(|c| self.secret_key * c.decompress().unwrap())
            .collect();
        let cs_decrypted_compressed: Vec<CompressedRistretto> =
            cs_decrypted.iter().map(|c| c.compress()).collect();

        let message: Vec<u8> = bincode::serialize(&cs_decrypted_compressed).unwrap();

        self.stream.write_all(&message).unwrap();
    }
}

impl Leader {
    /// Note that in this version, the leader does not have an input
    pub fn private_batched_composed_or(&mut self, compositions: &[Vec<usize>]) -> Vec<bool> {
        // 2. Sum of compositions and leader-randomization
        let received_ciphertexts: Vec<(Vec<CompressedRistretto>, Vec<CompressedRistretto>)> = self
            .streams
            .iter()
            .map(|stream| bincode::deserialize_from(stream).unwrap())
            .collect();

        let c1s_sum: Vec<RistrettoPoint> = compositions
            .iter()
            .map(|comp| {
                RistrettoPoint::sum(comp.iter().map(|i| {
                    RistrettoPoint::sum(
                        received_ciphertexts
                            .iter()
                            .map(|(c1, _)| c1[*i].decompress().unwrap()),
                    )
                }))
            })
            .collect();
        let c2s_sum: Vec<RistrettoPoint> = compositions
            .iter()
            .map(|comp| {
                RistrettoPoint::sum(comp.iter().map(|i| {
                    RistrettoPoint::sum(
                        received_ciphertexts
                            .iter()
                            .map(|(_, c2)| c2[*i].decompress().unwrap()),
                    )
                }))
            })
            .collect();

        let factors: Vec<Scalar> = (0..compositions.len())
            .map(|_| Scalar::random(&mut OsRng))
            .collect();

        let c1s_multiplied: Vec<RistrettoPoint> =
            c1s_sum.iter().zip(&factors).map(|(c1, r)| r * c1).collect();
        let c1s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c1s_multiplied);
        let c2s_multiplied: Vec<RistrettoPoint> =
            c2s_sum.iter().zip(&factors).map(|(c2, r)| r * c2).collect();
        let c2s_multiplied_compressed = RistrettoPoint::double_and_compress_batch(&c2s_multiplied);

        let message: Vec<u8> =
            bincode::serialize(&(c1s_multiplied_compressed, c2s_multiplied_compressed)).unwrap();

        self.streams.iter().for_each(|mut stream| {
            stream.write_all(&message).unwrap();
        });

        self.finish_or(false)
    }
}

impl Assistant {
    pub fn private_batched_composed_or(&mut self, bits: &[bool]) {
        self.private_batched_or(bits)
    }
}

impl Leader {
    pub fn private_batched_and(&mut self, bits: &[bool]) -> Vec<bool> {
        let inverted_bits: Vec<bool> = bits.iter().map(|b| !b).collect();
        self.private_batched_or(&inverted_bits, false)
            .iter()
            .map(|b| !b)
            .collect()
    }

    pub fn private_batched_composed_and(&mut self, compositions: &[Vec<usize>]) -> Vec<bool> {
        self.private_batched_composed_or(compositions)
            .iter()
            .map(|b| !b)
            .collect()
    }
}

impl Assistant {
    pub fn private_batched_and(&mut self, bits: &[bool]) {
        let inverted_bits: Vec<bool> = bits.iter().map(|b| !b).collect();
        self.private_batched_or(&inverted_bits);
    }

    pub fn private_batched_composed_and(&mut self, bits: &[bool]) {
        let inverted_bits: Vec<bool> = bits.iter().map(|b| !b).collect();
        self.private_batched_composed_or(&inverted_bits);
    }
}

/// Performs a multi-party private OR operation, consuming the inputs in the process.
pub fn mpo(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    party_bits: Vec<Vec<bool>>,
    timings: bool,
) -> Vec<bool> {
    let mut bits_iterator = party_bits.into_iter();
    let leader_bits = bits_iterator.next().unwrap();
    let leader_thread = thread::spawn(move || leader.private_batched_or(&leader_bits, timings));
    assistants
        .into_iter()
        .zip(bits_iterator)
        .for_each(|(mut assistant, bits)| {
            thread::spawn(move || assistant.private_batched_or(&bits));
        });

    leader_thread.join().unwrap()
}

/// Performs a multi-party private OR operation using the UNOPTIMIZED scheme, consuming the inputs in the process.
pub fn mpo_unoptimized(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    party_bits: Vec<Vec<bool>>,
    timings: bool,
) -> Vec<bool> {
    let mut bits_iterator = party_bits.into_iter();
    let leader_bits = bits_iterator.next().unwrap();
    let leader_thread =
        thread::spawn(move || leader.private_batched_or_unoptimized(&leader_bits, timings));
    assistants
        .into_iter()
        .zip(bits_iterator)
        .for_each(|(mut assistant, bits)| {
            thread::spawn(move || assistant.private_batched_or_unoptimized(&bits));
        });

    leader_thread.join().unwrap()
}

/// Performs a multi-party private AND operation, consuming the inputs in the process.
pub fn mpa(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    party_bits: Vec<Vec<bool>>,
) -> Vec<bool> {
    let mut bits_iterator = party_bits.into_iter();
    let leader_bits = bits_iterator.next().unwrap();
    let leader_thread = thread::spawn(move || leader.private_batched_and(&leader_bits));
    assistants
        .into_iter()
        .zip(bits_iterator)
        .for_each(|(mut assistant, bits)| {
            thread::spawn(move || assistant.private_batched_and(&bits));
        });

    leader_thread.join().unwrap()
}

/// Performs a multi-party private OR operation, consuming the inputs in the process.
pub fn mpco(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    compositions: Vec<Vec<usize>>,
    assistant_bits: Vec<Vec<bool>>,
) -> Vec<bool> {
    let leader_thread = thread::spawn(move || leader.private_batched_composed_or(&compositions));
    assistants
        .into_iter()
        .zip(assistant_bits)
        .for_each(|(mut assistant, bits)| {
            thread::spawn(move || assistant.private_batched_composed_or(&bits));
        });

    leader_thread.join().unwrap()
}
