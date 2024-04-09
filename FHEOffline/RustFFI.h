/**
 * Defines the Rust FFI interface for the FHEOffline library.
 */

#ifndef _RustFFI
#define _RustFFI

#include "FHE/AddableVector.h"
#include "FHE/Ciphertext.h"
#include "FHE/FHE_Keys.h"
#include "FHE/Plaintext.h"
#include "rust/cxx.h"

using PlaintextVector = AddableVector<Plaintext_mod_prime>;
using CiphertextVector = AddableVector<Ciphertext>;

/// Create a new plaintext vector
unique_ptr<PlaintextVector>
new_plaintext_vector(size_t size, const FHE_Params &params);

/// Create a new plaintext vector with a single element
unique_ptr<PlaintextVector> new_plaintext_vector_single(const Plaintext_mod_prime &plaintext);

/// Get an element from the plaintext vector
unique_ptr<Plaintext_mod_prime> get_plaintext_vector_element(const PlaintextVector &vector, size_t index);

/// Randomize the plaintexts in the vector
void randomize_plaintext_vector(PlaintextVector &vector);

/// Push a new plaintext to the vector
void push_plaintext_vector(PlaintextVector &vector, const Plaintext_mod_prime &plaintext);

/// Pop the last plaintext from the vector
void pop_plaintext_vector(PlaintextVector &vector);

/// Get the size of the vector
size_t plaintext_vector_size(const PlaintextVector &vector);

/// Create a new ciphertext vector
unique_ptr<CiphertextVector>
new_ciphertext_vector(size_t size, const FHE_Params &params);

/// Create a new ciphertext vector with a single element
unique_ptr<CiphertextVector> new_ciphertext_vector_single(const Ciphertext &ciphertext);

/// Get an element from the ciphertext vector
unique_ptr<Ciphertext> get_ciphertext_vector_element(const CiphertextVector &vector, size_t index);

/// Push a new ciphertext to the vector
void push_ciphertext_vector(CiphertextVector &vector, const Ciphertext &ciphertext);

/// Pop the last ciphertext from the vector
void pop_ciphertext_vector(CiphertextVector &vector);

/// Get the size of the vector
size_t ciphertext_vector_size(const CiphertextVector &vector);

/**
 * CiphertexrrtWithProof
 */

/// A ciphertext with a proof of knowledge of the plaintext
class CiphertextWithProof
{
public:
    int n_ciphertexts;
    octetStream proof_ciphertexts;
    octetStream proof_cleartexts;
    AddableVector<Ciphertext> enc;

    CiphertextWithProof(int n_ciphertexts, const octetStream &proof_ciphertexts, const octetStream &proof_cleartexts, const AddableVector<Ciphertext> &enc)
        : n_ciphertexts(n_ciphertexts), proof_ciphertexts(proof_ciphertexts), proof_cleartexts(proof_cleartexts), enc(enc) {}
};

/// Encrypt a batch of elements and prove knowledge of plaintext
unique_ptr<CiphertextWithProof> encrypt_and_prove_batch(const FHE_PK &pk, PlaintextVector &plaintexts, int sec = 128, bool diag = false);
/// Verify the proof of knowledge of plaintext
unique_ptr<CiphertextVector> verify_proof_of_knowledge(CiphertextWithProof &ciphertext_with_proof, const FHE_PK &pk, int sec = 128, bool diag = false);

#endif
