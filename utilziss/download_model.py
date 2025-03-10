import os
from huggingface_hub import hf_hub_download

API_KEY = "" # REMOVED FOR GITHUB

model_id = "mrm8488/codebert2codebert-finetuned-code-refinement-small"
filenames = [
    "config.json",
    "merges.txt",
    "pytorch_model.bin",
    "special_tokens_map.json",
    "tokenizer_config.json",
    "vocab.json",
]

for filename in filenames:
    print('Downloading',model_id,filename)
    downloaded_model_path = hf_hub_download(
        repo_id=model_id, filename=filename, token=API_KEY
    )

