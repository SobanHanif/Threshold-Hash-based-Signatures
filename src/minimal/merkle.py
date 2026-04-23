import hashlib


def leaf_hash(value):
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                parts.append(item[0])
                parts.append(item[1])
            else:
                parts.append(item)
        data = b"".join(parts)
    else:
        raise TypeError("unsupported public key type for leaf_hash")

    return hashlib.sha256(data).digest()


def build_merkle(leaves):
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        cur = []
        for i in range(0, len(prev), 2):
            left = prev[i]
            right = prev[i + 1] if i + 1 < len(prev) else prev[i]
            cur.append(hashlib.sha256(left + right).digest())
        levels.append(cur)
    return levels


def merkle_auth_path(levels, index):
    path = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx
        else:
            sibling_idx = idx - 1
        path.append(level[sibling_idx])
        idx //= 2
    return path


def merkle_root_from_path(leaf, index, path):
    cur = leaf
    idx = index
    for sibling in path:
        if idx % 2 == 0:
            cur = hashlib.sha256(cur + sibling).digest()
        else:
            cur = hashlib.sha256(sibling + cur).digest()
        idx //= 2
    return cur


def verify_merkle(leaf, index, path, root):
    return merkle_root_from_path(leaf, index, path) == root
