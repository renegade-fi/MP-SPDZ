
#include "FHEOffline/RustFFI.h"
#include "FHEOffline/Proof.h"
#include "FHEOffline/Prover.h"
#include "FHEOffline/Verifier.h"
#include "FHE/AddableVector.h"

/**
 * PlaintextVector
 */

// Factory functions
unique_ptr<PlaintextVector> new_plaintext_vector(size_t size, const FHE_Params &params)
{
    return make_unique<PlaintextVector>(size, params.get_plaintext_field_data<FFT_Data>());
}

unique_ptr<PlaintextVector> new_plaintext_vector_single(const Plaintext_mod_prime &plaintext)
{
    auto res = make_unique<PlaintextVector>(1, plaintext.get_field());
    (*res)[0] = plaintext;

    return res;
}

// Utility functions
unique_ptr<Plaintext_mod_prime> get_plaintext_vector_element(const PlaintextVector &vector, size_t index)
{
    return make_unique<Plaintext_mod_prime>(vector[index]);
}

void randomize_plaintext_vector(PlaintextVector &vector)
{
    PRNG G;
    G.ReSeed();
    vector.randomize(G);
}

void push_plaintext_vector(PlaintextVector &vector, const Plaintext_mod_prime &plaintext)
{
    vector.push_back(plaintext);
}

void pop_plaintext_vector(PlaintextVector &vector)
{
    vector.pop_back();
}

size_t plaintext_vector_size(const PlaintextVector &vector)
{
    return vector.size();
}

/**
 * CiphertextVector
 */

// Factory functions
unique_ptr<CiphertextVector> new_ciphertext_vector(size_t size, const FHE_Params &params)
{
    return make_unique<CiphertextVector>(size, params);
}

unique_ptr<CiphertextVector> new_ciphertext_vector_single(const Ciphertext &ciphertext)
{
    auto res = make_unique<CiphertextVector>(1, ciphertext.get_params());
    res->push_back(ciphertext);

    return res;
}

// Utility functions
unique_ptr<Ciphertext> get_ciphertext_vector_element(const CiphertextVector &vector, size_t index)
{
    return make_unique<Ciphertext>(vector[index]);
}

void push_ciphertext_vector(CiphertextVector &vector, const Ciphertext &ciphertext)
{
    vector.push_back(ciphertext);
}

void pop_ciphertext_vector(CiphertextVector &vector)
{
    vector.pop_back();
}

size_t ciphertext_vector_size(const CiphertextVector &vector)
{
    return vector.size();
}

/**
 * CiphertextWithProof
 */

/// Encrypt the value and store randomness
void encrypt_with_randomness(vector<Ciphertext> &ciphers, AddableVector<Plaintext_mod_prime> &plaintexts, Proof::Randomness &randomness, const FHE_PK &pk)
{
    PRNG rng;
    rng.ReSeed();

    auto n_ciphers = plaintexts.size();
    ciphers.resize(n_ciphers, pk);
    randomness.resize(n_ciphers, pk);

    // Generate an encryption for each plaintext
    Random_Coins coins(pk.get_params());
    for (unsigned i = 0; i < plaintexts.size(); i++)
    {
        randomness[i].sample(rng);
        coins.assign(randomness[i]);

        pk.encrypt(ciphers[i], plaintexts[i], coins);
    }
}

// FOR OPTIMIZATION
// 1. Don't encrypt, looks like the helpers do that for me
// 2. Decrease proof.U?
unique_ptr<CiphertextWithProof> encrypt_and_prove_batch(const FHE_PK &pk, PlaintextVector &plaintexts, int sec, bool diag)
{
    // Check the proof batching width
    unsigned int n = static_cast<unsigned int>(plaintexts.size());
    NonInteractiveProof proof(sec, pk, 1 /* n_proofs */, diag);
    if (proof.U < n)
    {
        throw runtime_error("Mismatch between proof width and number of plaintexts");
    }
    if (n == 0)
    {
        throw runtime_error("No plaintexts provided");
    }

    auto fd = plaintexts[0].get_field();
    plaintexts.resize(proof.U, fd);

    // Generate encryptions and store the randomness
    Proof::Randomness randomness(proof.U, pk.get_params());
    AddableVector<Ciphertext> ciphers(proof.U, pk);

    encrypt_with_randomness(ciphers, plaintexts, randomness, pk);

    // Prove knowledge of plaintext
    octetStream ciphertext_data;
    octetStream cleartext_data;

    Prover<FFT_Data, Plaintext_mod_prime> prover(proof, fd);
    prover.NIZKPoK(proof, ciphertext_data, cleartext_data, pk, ciphers, plaintexts, randomness);

    return unique_ptr<CiphertextWithProof>(new CiphertextWithProof(n, ciphertext_data, cleartext_data, ciphers));
}

unique_ptr<CiphertextVector> verify_proof_of_knowledge(CiphertextWithProof &ciphertext_with_proof, const FHE_PK &pk, int sec, bool diag)
{
    NonInteractiveProof proof(sec, pk, 1 /* n_proofs */, diag);
    CiphertextVector ciphers;

    FFT_Data fd = pk.get_params().get_plaintext_field_data<FFT_Data>();
    Verifier verifier(proof, fd);

    // Verify the proof
    verifier.NIZKPoK(ciphers, ciphertext_with_proof.proof_ciphertexts, ciphertext_with_proof.proof_cleartexts, pk);
    return make_unique<CiphertextVector>(ciphers);
}
