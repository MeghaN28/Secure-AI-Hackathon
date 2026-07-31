from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma


embeddings = OllamaEmbeddings(
    model="nomic-embed-text"
)


db = Chroma(
    persist_directory="./vector_db",
    embedding_function=embeddings
)


def retrieve_knowledge(query, k=3):

    results = db.similarity_search(
        query,
        k=2
)


    evidence = []


    for doc in results:

        evidence.append(
            {
                "content": doc.page_content[:1500],
                "source": doc.metadata.get("source")
            }
        )


    return evidence