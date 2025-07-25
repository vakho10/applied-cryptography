# Part 2: Code Obfuscation Challenge

# Apply manual obfuscation: rename variables to meaningless values.
def f(x):
    if x <= 0:
        return []
    elif x == 1:
        return [0]
    a = [0, 1]
    for b in range(2, x):
        a.append(a[-1] + a[-2])
    return a

# For obfuscation we may use: pyminifier, or pyarmor.
# Let's use pyarmor:
# `.venv\Scripts\activate`
# `python -m pip install --upgrade pip`
# `python -m pip install pyarmor`
# `python pyarmor-7 obfuscate --restrict=0 fibonacci.py`

# Explanation:
# Obfuscation means changing code to some unreadable but functional counterpart that is hard to understand
# for malicious attackers.
# Manual obfuscation may seem easier, but it is not strong enough. It can be easily cracked.
# On the other hand, automatic obfuscation provides stronger protection against reverse engineering of compiled bytecode,
# decompilation attempts, intellectual property thefts, and tampering with the code logic.