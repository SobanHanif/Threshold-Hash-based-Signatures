import hashlib
import secrets

def leaf_hash(wots_pk):
  # wots_pk is a list of 32 byte hash chain final values
  # im cheating
  if isinstance(wots_pk, list):
    return hashlib.sha256("".join(wots_pk)).digest()
  return hashlib.sha256(wots_pk).digest()

def build_merkle(leaves):
  # binary merkle tree w/ odd nodes duplicating the last sibling
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


def verify_merkle(leaf, index, path, root):
  cur = leaf
  idx = index
  for sibling in path:
    if idx % 2 == 0:
      cur = hashlib.sha256(cur + sibling).digest()
    else:
      cur = hashlib.sha256(sibling + cur).digest()
    idx //= 2
  return cur == root
