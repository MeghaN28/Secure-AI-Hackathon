from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_community.vectorstores import Chroma

print("Loading PDFs...")

loader = PyPDFDirectoryLoader("knowledge_base")
documents = loader.load()

print(f"Loaded {len(documents)} pages")

splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200
)

chunks = splitter.split_documents(documents)

print(f"Created {len(chunks)} chunks")

embeddings = OllamaEmbeddings(
    model="nomic-embed-text"
)

print("Creating vector database...")

db = Chroma.from_documents(
    documents=chunks,
    embedding=embeddings,
    persist_directory="vector_db"
)

print("Knowledge base created successfully!")