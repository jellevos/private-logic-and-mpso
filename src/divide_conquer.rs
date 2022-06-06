use crate::{Assistant, Leader};
use std::thread;
use std::thread::JoinHandle;

fn split(min_index: &usize, max_index: &usize, divisions: usize) -> Vec<(usize, usize)> {
    let chunk_size = (max_index - min_index) as f64 / divisions as f64;

    let mut indices = Vec::with_capacity(divisions);

    let mut min = *min_index as f64;
    for _ in 0..divisions {
        let max = min + chunk_size;
        indices.push((min.round() as usize, max.round() as usize));

        min = max;
    }

    indices
}

pub fn divide_and_conquer_or(
    mut leader: Leader,
    mut assistants: Vec<Assistant>,
    party_bits: Vec<Vec<bool>>,
    divisions: usize,
) -> Vec<bool> {
    let mut result: Vec<bool> = vec![false; party_bits[0].len()];
    let mut previous_indices: Vec<(usize, usize)> = vec![(0, party_bits[0].len())];

    loop {
        let mut indices: Vec<(usize, usize)> =
            Vec::with_capacity(previous_indices.len() * divisions);
        for (min_index, max_index) in previous_indices {
            indices.extend(
                split(&min_index, &max_index, divisions)
                    .iter()
                    .map(|(min, max)| (*min, *max)),
            );
        }

        let mut party_round_bits = Vec::with_capacity(party_bits.len());

        for bits in &party_bits {
            let mut round_bits: Vec<bool> = Vec::with_capacity(indices.len());

            for (min_index, max_index) in &indices {
                round_bits.push(
                    bits[*min_index..*max_index]
                        .iter()
                        .fold(false, |a, b| a | b),
                );
            }

            party_round_bits.push(round_bits);
        }

        let mut round_bits_iterator = party_round_bits.into_iter();
        let leader_round_bits = round_bits_iterator.next().unwrap();
        let leader_thread =
            thread::spawn(move || (leader.private_batched_or(&leader_round_bits, false), leader));
        let assistant_threads: Vec<JoinHandle<_>> = assistants
            .into_iter()
            .zip(round_bits_iterator)
            .map(|(mut assistant, round_bits)| {
                thread::spawn(move || {
                    assistant.private_batched_or(&round_bits);
                    assistant
                })
            })
            .collect();

        let (ors, leader_next) = leader_thread.join().unwrap();
        leader = leader_next;
        assistants = vec![];
        for t in assistant_threads {
            assistants.push(t.join().unwrap());
        }

        previous_indices = Vec::with_capacity(ors.len());
        for (or, (min, max)) in ors.iter().zip(indices) {
            if (max - min) == 1 {
                result[min] = *or;
                continue;
            }

            if *or {
                previous_indices.push((min, max));
            }
        }

        if previous_indices.is_empty() {
            return result;
        }
    }
}
