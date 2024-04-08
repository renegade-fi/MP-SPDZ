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

/// A vector of plaintexts that can be added together
class PlaintextVector
{
    AddableVector<Plaintext_mod_prime> plaintexts;

public:
    PlaintextVector();
    PlaintextVector(const Plaintext_mod_prime &plaintext);
    PlaintextVector(size_t size, FFT_Data &fd);
    PlaintextVector(size_t size, const FHE_Params &params);
    PlaintextVector(const PlaintextVector &other);

    Plaintext_mod_prime operator[](size_t i) const;

    void randomize();
    void push_back(const Plaintext_mod_prime &plaintext);
    void resize(size_t size, FFT_Data &fd);
    void pop_back();
    size_t size() const;

    PlaintextVector &operator=(const PlaintextVector &other);

    const AddableVector<Plaintext_mod_prime> &get_addable() const;
};

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

#endif
