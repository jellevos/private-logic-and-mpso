use crate::{
    oprf::{hash_leader_elements_assistant, hash_leader_elements_leader},
    Assistant, Leader,
};
use sets_multisets::{
    bloom_filters::{bloom_filter_indices, ElementHasher},
    sets::Set,
};
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

pub fn mpsi_large<H: ElementHasher>(
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
            .map(|element| bloom_filter_indices::<H>(element, bin_count, hash_count).collect())
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
                assistant
                    .private_batched_composed_and(&set.to_bloom_filter::<H>(bin_count, hash_count))
            });
        });

    leader_thread.join().unwrap()
}

pub fn mpsi_large_oprf(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    sets: Vec<Set>,
    bin_count: usize,
    hash_count: usize,
) -> Set {
    let n = sets.len();

    let leader_set = sets.get(0).unwrap().clone();

    // This is hacky... We let the leader run the OPRFs on each set and then just transfer the indices to the assistants.
    // This is not how the protocol runs in real life: there, each assistant runs the protocol for itself.
    let leader_thread = thread::spawn(move || {
        (
            sets.into_iter()
                .map(|set| hash_leader_elements_leader(&mut leader, set, bin_count, hash_count))
                .collect::<Vec<_>>(),
            leader,
        )
    });
    let assistant_threads: Vec<_> = assistants
        .into_iter()
        .map(|mut assistant| {
            thread::spawn(move || {
                for _ in 0..n {
                    hash_leader_elements_assistant(&mut assistant);
                }
                assistant
            })
        })
        .collect();

    let assistants: Vec<Assistant> = assistant_threads
        .into_iter()
        .map(|assistant_thread| assistant_thread.join().unwrap())
        .collect();
    let (indices_per_party, mut leader) = leader_thread.join().unwrap();

    // Now run the Bloom filter-based MPSI
    let mut indices_per_party_iter = indices_per_party.into_iter();
    let leader_indices = indices_per_party_iter.next().unwrap();

    let leader_thread = thread::spawn(move || {
        let result = leader.private_batched_composed_and(&leader_indices);

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
        .zip(indices_per_party_iter)
        .for_each(|(mut assistant, indices)| {
            thread::spawn(move || {
                let mut bloom_filter = vec![false; bin_count];
                for index in indices.into_iter().flat_map(|index| index) {
                    bloom_filter[index] = true;
                }
                assistant.private_batched_composed_and(&bloom_filter);
            });
        });

    leader_thread.join().unwrap()
}
