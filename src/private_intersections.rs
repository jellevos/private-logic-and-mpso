use crate::{Assistant, Leader};
use sets_multisets::sets::{bloom_filter_indices, Set};
use std::thread;

pub fn mpsi_small(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    sets: Vec<Set>,
    universe: usize,
) -> Set {
    let mut set_iterator = sets.into_iter();
    let leader_set = set_iterator.next().unwrap();
    let leader_thread =
        thread::spawn(move || leader.private_batched_and(&leader_set.to_bitset(universe)));
    assistants
        .into_iter()
        .zip(set_iterator)
        .for_each(|(mut assistant, set)| {
            thread::spawn(move || assistant.private_batched_and(&set.to_bitset(universe)));
        });

    Set::from_bitset(&leader_thread.join().unwrap())
}

pub fn mpsi_large(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    sets: Vec<Set>,
    bin_count: usize,
    hash_count: usize,
) -> Set {
    let mut set_iterator = sets.into_iter();
    let leader_set = set_iterator.next().unwrap();
    let leader_thread = thread::spawn(move || {
        let compositions: Vec<Vec<usize>> = leader_set
            .elements
            .iter()
            .map(|element| bloom_filter_indices(element, bin_count, hash_count).collect())
            .collect();
        let result = leader.private_batched_composed_and(&compositions);

        leader_set
            .elements
            .iter()
            .zip(result)
            .filter(|(_, res)| *res)
            .map(|(el, _)| el)
            .copied()
            .collect()
    });
    assistants
        .into_iter()
        .zip(set_iterator)
        .for_each(|(mut assistant, set)| {
            thread::spawn(move || {
                assistant.private_batched_composed_and(&set.to_bloom_filter(bin_count, hash_count))
            });
        });

    leader_thread.join().unwrap()
}
