import pymongo

class router_service:
    def __init__(self, db_name, connection_string="mongodb://localhost:27017/"):
        # Connect to MongoDB
        self.client = pymongo.MongoClient(connection_string)
        # Access the specified database
        self.db = self.client[db_name]
        # Access the specified collection
        self.collection = self.db["router"]


    def get_routers(self):
        """Retrieve all documents from the collection without the _id field."""
        projection = {'_id': 0}  # Exclude _id field
        return list(self.collection.find({},projection))

    def get_router(self, name):
        projection = {'_id': 0}  # Exclude _id field
        return self.collection.find_one({"name":name}, projection)

    def add_router(self, new_router: dict):
        document = {"name": new_router["name"],
                    "connection": new_router["connection"],
                    "interface": new_router["interface"],}
        insert_result = self.collection.insert_one(document)
        return f"Inserted document ID: {insert_result.inserted_id}"

    def delete_router_by_name(self, name):
        """Delete a document from the collection."""
        delete_result = self.collection.delete_one({"name":name})
        return f"Number of documents deleted: {delete_result.deleted_count}"


    def update_router(self, query, new_values):
        """Update a document in the collection."""
        update_result = self.collection.update_one(query, new_values)
        return f"Number of documents updated: {update_result.modified_count}"

    def find_router_by_ip(self, ip):
        """Find a specific document by an IP address in the interface array."""
        query = {"interface": ip}
        projection = {'_id': 0}  # Exclude _id field
        document = self.collection.find_one(query, projection)
        return document

