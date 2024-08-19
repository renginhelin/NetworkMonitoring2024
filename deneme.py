import pymongo

class db_operations:
    def __init__(self, db_name, collection_name, connection_string="mongodb://localhost:27017/"):
        # Connect to MongoDB
        self.client = pymongo.MongoClient(connection_string)
        # Access the specified database
        self.db = self.client[db_name]
        # Access the specified collection
        self.collection = self.db[collection_name]

    def insert_document(self, document):
        """Insert a new document into the collection."""
        insert_result = self.collection.insert_one(document)
        return f"Inserted document ID: {insert_result.inserted_id}"

    def update_document(self, query, new_values):
        """Update a document in the collection."""
        update_result = self.collection.update_one(query, new_values)
        return f"Number of documents updated: {update_result.modified_count}"

    def delete_document(self, query):
        """Delete a document from the collection."""
        delete_result = self.collection.delete_one(query)
        return f"Number of documents deleted: {delete_result.deleted_count}"

    def find_documents(self, query={}):
        """Retrieve all documents from the collection without the _id field."""
        projection = {'_id': 0}  # Exclude _id field
        return list(self.collection.find(query, projection))

    def find_document_by_host(self, name):
        """Find a specific document by host."""
        query = {"name": name}
        projection = {'_id': 0}  # Exclude _id field
        document = self.collection.find_one(query, projection)
        return document
