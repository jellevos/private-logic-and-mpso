

// Each party interacts with all other parties (and itself) in an OPRF to hash their inputs.
// So, one input creates n hashes, which it combines using a KDF.
// All parties must input the hashes in a consistent ordering.

// We just implement it for the leader, and then we multiply the run time and bandwidth to reflect that the assistants must also perform this operation.

use std::io::Write;

use rand::{rngs::{OsRng, ThreadRng}, thread_rng};
use sets_multisets::sets::Set;
use voprf::{OprfClient, OprfClientBlindResult, OprfServer};

use crate::private_logic::{Assistant, Leader};

type CipherSuite = voprf::Ristretto255;

struct OprfLeader {
    leader: Leader,
    server: OprfServer<CipherSuite>,
}

struct OprfAssistant {
    assistant: Assistant,
    server: OprfServer<CipherSuite>,
}

impl OprfLeader {
    pub fn new(leader: Leader) -> Self {
        let mut thread_rng = thread_rng();
        Self {
            leader,
            server: OprfServer::new(&mut thread_rng),
        }
    }

    pub fn hash_elements(&mut self, leader_set: Set, hash_count: usize) -> Vec<Vec<usize>> {
        let n = self.leader.streams.len();

        // Initiate OPRFs with each assistant
        let client_blind_results_per_assistant: Vec<Vec<OprfClientBlindResult<CipherSuite>>> = self.leader.streams[1..n].iter().map(|assistant| {
            let client_blind_results: Vec<OprfClientBlindResult<CipherSuite>> = leader_set
                .elements
                .iter()
                .map(|element| {
                    client_rng = thread_rng();
                    let bytes = element.to_be_bytes();
                    OprfClient::blind(&bytes, &mut client_rng)
                    .expect("Unable to construct client");
                })
                .collect();

            // Send message
            let mut message: Vec<u8> = bincode::serialize(&client_blind_results.iter().map(|client_blind_result| client_blind_result.message.serialize().to_vec()).collect::<Vec<_>>());
            assistant.write_all(&message);

            client_blind_results
        }).collect();

        // Finish OPRFs with each assistant (each assistant replies with k messages)
        let element_hashes_per_assistant: Vec<_> = self.leader.streams[1..n].iter().zip(client_blind_results_per_assistant).map(|(assistant, client_blind_results, )| {
            let messages: Vec<Vec<u8>> = bincode::deserialize_from(assistant).unwrap();

            let element_hashes: Vec<Vec<u8>> = client_blind_results.iter().zip(leader_set.elements.iter()).zip(messages).map(|((client_blind_result, element,), message)| {
                let bytes = element.to_be_bytes();
                client_blind_result.finalize(&bytes, &message).expect("Unable to perform client finalization").to_vec()
            }).collect();

            element_hashes
        }).collect();
        
        leader_set.elements.iter().map(|element| {
            let bytes = element.to_be_bytes();
            let mut key_material = self.server.evaluate(&bytes).unwrap().to_vec();
            key_material.extend((0..n).flat_map(|j| element_hashes_per_assistant[j]).collect());

            let hk = Hkdf::<Sha256>::new(None, key_material);
            (0..hash_count).map(|seed| {
                let mut output_bytes = [0u8; 8];
                hk.expand([j], &mut output_bytes).unwrap();
                usize::from_be_bytes(output_bytes)
            }).collect()
        }).collect()
    }
}

impl OprfAssistant {
    pub fn new(assistant: Assistant) -> Self {
        let mut thread_rng = thread_rng();
        Self {
            assistant,
            server: OprfServer::new(&mut thread_rng),
        }
    }

    pub fn hash_elements(&mut self, assistant_set: Set) -> impl Iterator<Item = usize> {
        // Read the OPRF messages 
    }
}
