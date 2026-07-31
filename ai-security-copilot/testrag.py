from rag_retriever import retrieve_knowledge


queries = [
    "NIST FIPS 203 ML-KEM migration guidance",
    "NIST post quantum cryptography RSA replacement",
    "FIPS 204 ML-DSA digital signatures",
    "SHA-1 transition guidance SP 800-131A",
]


for query in queries:

    print("\n==============================")
    print("QUERY:")
    print(query)

    results = retrieve_knowledge(
        query,
        k=3
    )

    print("\nRESULTS:")

    if not results:
        print("NO RESULTS")

    for item in results:

        print("\nSOURCE:")
        print(item["source"])

        print("\nCONTENT:")
        print(item["content"][:500])