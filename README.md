# blkChain

blkChain provides local knowledge retrieval for authorized security research.
The corpus and model weights are supplied separately.

## Components

- Python builds and updates the corpus index.
- The model server provides embedding and reranking over HTTP.
- The Go terminal client provides search and grounded answers.

Configuration uses environment variables. Model weights, corpus data, and
credentials remain outside version control.
