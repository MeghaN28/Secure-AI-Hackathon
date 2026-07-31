from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

embeddings = OllamaEmbeddings(
    model="nomic-embed-text"
)

db = Chroma(
    persist_directory="./vector_db",
    embedding_function=embeddings
)

query = input("Ask a question: ")

results = db.similarity_search(query, k=3)

print("\n===== RETRIEVED EVIDENCE =====\n")

for i, doc in enumerate(results, start=1):
    print(f"Document {i}")
    print("-" * 60)
    print(doc.page_content[:1000])
    print()
    print("Source:", doc.metadata.get("source"))
    print("=" * 60)