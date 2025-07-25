# Part 1: Zero-Knowledge Proof (ZKP) Simulation

import random


def simulate_zkp(trials, knows_password):
    success_count = 0
    for _ in range(trials):
        path_entered = random.choice(['A', 'B'])
        challenge = random.choice(['A', 'B'])

        if knows_password:
            success = True
        else:
            success = path_entered == challenge

        if success: success_count += 1

    print(f"Successful responses: {success_count}/{trials}")
    success_rate = success_count / trials
    print(f"Success probability: {success_rate:.2f}")


if __name__ == '__main__':
    simulate_zkp(20, False)
