import sqlite3
import googlemaps
import matplotlib.pyplot as plt
import folium


# Connect to the SQLite database
conn = sqlite3.connect('I:\\Siscods\\2023\\05. Maio\\Garmin\\out-db\\garmin_locations.db')
cursor = conn.cursor()

# Fetch latitude and longitude values from the "locations" table
cursor.execute('SELECT reg_lat, reg_long FROM garmin_locations where lower(reg_lat) like \'%16%\'')
results = cursor.fetchall()

# Initialize Google Maps client with your API key
gmaps = googlemaps.Client(key='')

# Create a map centered at the first location
first_location = results[0]
map_center = float(first_location[0]), float(first_location[1])
mymap = folium.Map(location=map_center, zoom_start=12)

# Add markers for each location
for location in results:
    latitude = float(location[0])
    longitude = float(location[1])
    #address = gmaps.reverse_geocode((latitude, longitude))[0]['formatted_address']
    #marker = folium.Marker(location=(latitude, longitude), popup=address)
    marker = folium.Marker(location=(latitude, longitude))
    mymap.add_child(marker)

# Save the map as an HTML file
mymap.save('map.html')

# Close the database connection
cursor.close()
conn.close()