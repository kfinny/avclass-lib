from os.path import join, split

_HASH_TYPE_MAP = {
    "md5": 32,
    32: "md5",
    "sha1": 40,
    40: "sha1",
    "sha256": 64,
    64: "sha256"}


def hash_type(hashval):
    """Given a hash string, guess the hash type based on the string length"""
    return _HASH_TYPE_MAP.get(len(hashval), None)


def get_data_file_path(name):
    return join(split(__file__)[0], "data", name)


def pick_hash(sample_info):
    for attr in ['sha256', 'sha1', 'md5']:
        if hasattr(sample_info, attr):
            v = getattr(sample_info, attr)
            if v is not None:
                return v
    return None
