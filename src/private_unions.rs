use crate::divide_conquer::divide_and_conquer_or;
use crate::{Assistant, Leader};
use sets_multisets::sets::Set;
use std::thread;

pub fn mpsu_small(
    mut leader: Leader,
    assistants: Vec<Assistant>,
    sets: Vec<Set>,
    universe: usize,
) -> Set {
    let mut set_iterator = sets.into_iter();
    let leader_set = set_iterator.next().unwrap();
    let leader_thread =
        thread::spawn(move || leader.private_batched_or(&leader_set.to_bitset(universe), false));
    assistants
        .into_iter()
        .zip(set_iterator)
        .for_each(|(mut assistant, set)| {
            thread::spawn(move || assistant.private_batched_or(&set.to_bitset(universe)));
        });

    Set::from_bitset(&leader_thread.join().unwrap())
}

pub fn mpsu_large(
    leader: Leader,
    assistants: Vec<Assistant>,
    sets: Vec<Set>,
    universe: usize,
    divisions: usize,
) -> Set {
    // TODO: Consider keeping sets as sparse ordered representations, so not to make huge bitsets

    Set::from_bitset(&divide_and_conquer_or(
        leader,
        assistants,
        sets.iter().map(|set| set.to_bitset(universe)).collect(),
        divisions,
    ))
}
