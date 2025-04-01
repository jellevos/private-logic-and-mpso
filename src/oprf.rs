// Each party interacts with all other parties (and itself) in an OPRF to hash their inputs.
// So, one input creates n hashes, which it combines using a KDF.
// All parties must input the hashes in a consistent ordering.

// We just implement it for the leader, and then we multiply the run time and bandwidth to reflect that the assistants must also perform this operation.

use std::io::Write;

use hkdf::Hkdf;
use rand::thread_rng;
use sets_multisets::sets::Set;
use sha2::Sha256;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfClientBlindResult, OprfServer};

use crate::private_logic::{Assistant, Leader};

type CipherSuite = voprf::Ristretto255;

struct OprfLeader<'a> {
    leader: &'a mut Leader,
    server: OprfServer<CipherSuite>,
}

struct OprfAssistant<'a> {
    assistant: &'a mut Assistant,
    server: OprfServer<CipherSuite>,
}

impl<'a> OprfLeader<'a> {
    pub fn new(leader: &'a mut Leader) -> Self {
        let mut thread_rng = thread_rng();
        Self {
            leader,
            server: OprfServer::new(&mut thread_rng).unwrap(),
        }
    }

    pub fn hash_elements(
        &mut self,
        leader_set: Set,
        bin_count: usize,
        hash_count: usize,
    ) -> Vec<Vec<usize>> {
        let n = self.leader.streams.len();

        // Initiate OPRFs with each assistant
        let client_blind_results_per_assistant: Vec<Vec<OprfClientBlindResult<CipherSuite>>> = self
            .leader
            .streams[0..n]
            .iter()
            .map(|mut assistant| {
                let client_blind_results: Vec<OprfClientBlindResult<CipherSuite>> = leader_set
                    .elements
                    .iter()
                    .map(|element| {
                        let mut client_rng = thread_rng();
                        let bytes = element.to_be_bytes();
                        OprfClient::blind(&bytes, &mut client_rng)
                            .expect("Unable to construct client")
                    })
                    .collect();

                // Send message
                let mut message: Vec<u8> = bincode::serialize(
                    &client_blind_results
                        .iter()
                        .map(|client_blind_result| client_blind_result.message.serialize().to_vec())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                assistant.write_all(&mut message);

                client_blind_results
            })
            .collect();

        // Finish OPRFs with each assistant (each assistant replies with k messages)
        let element_hashes_per_assistant: Vec<_> = self.leader.streams[0..n]
            .iter()
            .zip(client_blind_results_per_assistant)
            .map(|(assistant, client_blind_results)| {
                let messages: Vec<Vec<u8>> = bincode::deserialize_from(assistant).unwrap();

                let element_hashes: Vec<Vec<u8>> = client_blind_results
                    .iter()
                    .zip(leader_set.elements.iter())
                    .zip(messages)
                    .map(|((client_blind_result, element), message)| {
                        let bytes = element.to_be_bytes();
                        let evaluation_element = EvaluationElement::deserialize(&message).unwrap();
                        client_blind_result
                            .state
                            .finalize(&bytes, &evaluation_element)
                            .expect("Unable to perform client finalization")
                            .to_vec()
                    })
                    .collect();

                element_hashes
            })
            .collect();

        leader_set
            .elements
            .iter()
            .enumerate()
            .map(|(index, element)| {
                let bytes = element.to_be_bytes();
                let mut key_material: Vec<u8> = self.server.evaluate(&bytes).unwrap().to_vec();
                key_material.extend((0..n).flat_map(|j| &element_hashes_per_assistant[j][index]));

                let hk = Hkdf::<Sha256>::new(None, &key_material);
                (0..hash_count)
                    .map(|seed| {
                        let mut output_bytes = [0u8; 8];
                        hk.expand(&seed.to_be_bytes(), &mut output_bytes).unwrap();
                        usize::from_be_bytes(output_bytes) % bin_count
                    })
                    .collect()
            })
            .collect()
    }
}

impl<'a> OprfAssistant<'a> {
    pub fn new(assistant: &'a mut Assistant) -> Self {
        let mut thread_rng = thread_rng();
        Self {
            assistant,
            server: OprfServer::new(&mut thread_rng).unwrap(),
        }
    }

    pub fn hash_elements(&mut self) {
        // Reply to the OPRF messages
        let messages: Vec<Vec<u8>> = bincode::deserialize_from(&self.assistant.stream).unwrap();

        let replies: Vec<Vec<u8>> = messages
            .into_iter()
            .map(|message| {
                let server_evaluate_result = self
                    .server
                    .blind_evaluate(&BlindedElement::deserialize(&message).unwrap());
                server_evaluate_result.serialize().to_vec()
            })
            .collect();

        bincode::serialize_into(&mut self.assistant.stream, &replies);
    }
}

pub fn hash_leader_elements_leader(
    leader: &mut Leader,
    leader_set: Set,
    bin_count: usize,
    hash_count: usize,
) -> Vec<Vec<usize>> {
    let mut oprf_leader = OprfLeader::new(leader);
    oprf_leader.hash_elements(leader_set, bin_count, hash_count)
}

pub fn hash_leader_elements_assistant(assistant: &mut Assistant) {
    let mut oprf_assistant = OprfAssistant::new(assistant);
    oprf_assistant.hash_elements();
}
