def clean_key(key):
    lines = key.splitlines()
    filtered_list = [x for x in lines if not any(y in x for y in ["Version", "Comment", "MessageID", "Hash", "Charset"])]
    filtered_key = "\n".join(filtered_list).replace("\n\n", "\n")
    return filtered_key