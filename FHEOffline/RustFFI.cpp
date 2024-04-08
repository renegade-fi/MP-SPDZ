
#include "FHEOffline/RustFFI.h"
#include "FHEOffline/Proof.h"
#include "FHEOffline/Prover.h"

/**
 * PlaintextVector
 */
#include "FHEOffline/RustFFI.h"

// Constructors
PlaintextVector::PlaintextVector() {}

PlaintextVector::PlaintextVector(const Plaintext_mod_prime &plaintext) : plaintexts(1, plaintext) {}

PlaintextVector::PlaintextVector(size_t size, FFT_Data &fd) : plaintexts(size, fd) {}

PlaintextVector::PlaintextVector(size_t size, const FHE_Params &params) : plaintexts(size, params.get_plaintext_field_data<FFT_Data>()) {}

PlaintextVector::PlaintextVector(const PlaintextVector &other) : plaintexts(other.plaintexts) {}

// Assignment operator
PlaintextVector &PlaintextVector::operator=(const PlaintextVector &other)
{
    if (this != &other)
    {
        plaintexts = other.plaintexts;
    }
    return *this;
}

// Element access
Plaintext_mod_prime PlaintextVector::operator[](size_t i) const
{
    return plaintexts[i];
}

// Modifiers
void PlaintextVector::randomize()
{
    PRNG G;
    G.ReSeed();
    plaintexts.randomize(G);
}

void PlaintextVector::push_back(const Plaintext_mod_prime &plaintext)
{
    plaintexts.push_back(plaintext);
}

void PlaintextVector::resize(size_t size, FFT_Data &fd)
{
    plaintexts.resize(size, fd);
}

void PlaintextVector::pop_back()
{
    plaintexts.pop_back();
}

// Capacity
size_t PlaintextVector::size() const
{
    return plaintexts.size();
}

// Getters
const AddableVector<Plaintext_mod_prime> &PlaintextVector::get_addable() const
{
    return plaintexts;
}

// Factory functions
unique_ptr<PlaintextVector> new_plaintext_vector(size_t size, const FHE_Params &params)
{
    return make_unique<PlaintextVector>(size, params);
}

unique_ptr<PlaintextVector> new_plaintext_vector_single(const Plaintext_mod_prime &plaintext)
{
    return make_unique<PlaintextVector>(plaintext);
}

// Utility functions
unique_ptr<Plaintext_mod_prime> get_plaintext_vector_element(const PlaintextVector &vector, size_t index)
{
    return make_unique<Plaintext_mod_prime>(vector[index]);
}

void randomize_plaintext_vector(PlaintextVector &vector)
{
    vector.randomize();
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

unique_ptr<CiphertextWithProof> encrypt_and_prove_batch(const FHE_PK &pk, PlaintextVector &plaintexts, int sec, bool diag)
{
    cout << "got here" << endl;
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
    auto addable = plaintexts.get_addable();
    cout << "got here 1" << endl;

    // Generate encryptions and store the randomness
    Proof::Randomness randomness(proof.U, pk.get_params());
    AddableVector<Ciphertext> ciphers(proof.U, pk);
    cout << "got here 2" << endl;

    encrypt_with_randomness(ciphers, addable, randomness, pk);
    cout << "got here 3" << endl;

    // Prove knowledge of plaintext
    octetStream ciphertext_data;
    octetStream cleartext_data;

    Prover<FFT_Data, Plaintext_mod_prime> prover(proof, fd);
    cout << "got here 4" << endl;
    prover.NIZKPoK(proof, ciphertext_data, cleartext_data, pk, ciphers, addable, randomness);
    cout << "got here 5" << endl;

    return unique_ptr<CiphertextWithProof>(new CiphertextWithProof(n, ciphertext_data, cleartext_data, ciphers));
}
