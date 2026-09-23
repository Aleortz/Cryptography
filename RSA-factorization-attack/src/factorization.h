#ifndef FACTORIZATION_H
#define FACTORIZATION_H

#include <cstdint>
#include <utility>

namespace rsa_attack {
	
    std::pair<uint64_t, uint64_t> trial_division(uint64_t n);
	std::pair<uint64_t, uint64_t>fermat_factorization(uint64_t n, uint64_t* iters = nullptr);
	std::pair<uint64_t, uint64_t>pollards_rho(uint64_t n);
	}

#endif