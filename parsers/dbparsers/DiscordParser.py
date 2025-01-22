import sqlite3
import json

# Replace 'your_database.db' with the actual path to your SQLite database
db_path = 'I:\\a.sqlite'

# Connect to the SQLite database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Replace 'messages' with the actual table name
table_name = 'messages0'

# Query to select all rows from the 'messages' table
select_query = f'SELECT data FROM {table_name}'

# Execute the query
cursor.execute(select_query)

# Fetch all rows
rows = cursor.fetchall()

# Iterate through each row
for row in rows:
    # The index 0 corresponds to the column containing the JSON data
    json_data = row[0]

    # Parse the JSON data
    try:
        data = json.loads(json_data[1:])

        # Extract the required fields
        author_username = data['message']['author']['username']
        content = data['message']['content']
        timestamp = data['message']['timestamp']

        # Print the extracted fields
        print(f"{timestamp} - {author_username}: {content}")

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")

# Close the database connection
conn.close()