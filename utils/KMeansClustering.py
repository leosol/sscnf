from datetime import datetime, timedelta
import matplotlib.patches as mpatches
from adjustText import adjust_text
from decimal import *
import random
import matplotlib.pyplot as plt
import sqlite3
import sys
from bokeh.plotting import gmap
from bokeh.models import GMapOptions
from bokeh.io import output_file, show


class KMeansClustering:
    def __init__(self, k, max_iterations, data, dimensions_index):
        self.k = k
        self.max_iterations = max_iterations
        self.data = data
        self.clusters = {}
        self.cluster_allocation = {}
        self.dimensions_index = dimensions_index
        self.adjust_text = False
        self.show_text = False
        self.data_with_grouping = False
        self.data_grouping_index = -1
        self.show_legends = False

    def create_clusters(self):
        selected_clusters = set()
        while len(selected_clusters) < self.k:
            rnd = random.randint(0, len(self.data) - 1)
            selected_clusters.add(rnd)
        print("Selected Clusters: " + str(selected_clusters))
        pos = 0
        for i in selected_clusters:
            self.clusters[pos] = (self.data[i].copy())
            pos = pos + 1

    def set_clusters(self, clusters_positions):
        pos = 0
        for i in clusters_positions:
            self.clusters[pos] = (self.data[i].copy())
            pos = pos + 1
        self.k = len(clusters_positions)

    def calc_distance(self, item, clsr):
        distance = Decimal(0)
        for i in self.dimensions_index:
            distance = distance + Decimal((item[i] - clsr[i]) ** 2)
        return distance.sqrt()

    def find_cluster_index(self, item):
        closest_distance = Context(Emax=MAX_EMAX, prec=1).create_decimal('9e' + str(MAX_EMAX))
        closest_index = -1
        for i in self.clusters:
            d = self.calc_distance(item, self.clusters[i])
            if d < closest_distance:
                closest_index = i
                closest_distance = d
        return closest_index, closest_distance

    def assign_to_clusters(self):
        data_clusters = {}
        for i in self.data:
            closest_clsr_index, closest_clsr_distance = self.find_cluster_index(self.data[i])
            data_clusters[i] = closest_clsr_index
        return data_clusters

    def dicts_are_equal(self, a, b):
        len_a = len(a)
        len_b = len(b)
        if len_a != len_b:
            return False
        for i in range(0, len_a):
            if a[i] != b[i]:
                return False
        return True

    def compute_centroids(self):
        clusters_assignment_count = {}
        for i in range(0, len(self.clusters)):
            clusters_assignment_count[i] = Decimal(0)
            for j in self.dimensions_index:
                self.clusters[i][j] = Decimal(0)

        for i in range(0, len(self.data)):
            data_item = self.data[i]
            data_cluster_index = self.cluster_allocation[i]
            cluster = self.clusters[data_cluster_index]
            clusters_assignment_count[data_cluster_index] = clusters_assignment_count[data_cluster_index] + 1
            for j in self.dimensions_index:
                cluster[j] = cluster[j] + Decimal(data_item[j])

        for i in range(0, len(self.clusters)):
            for j in self.dimensions_index:
                if clusters_assignment_count[i]>0:
                    self.clusters[i][j] = self.clusters[i][j] / clusters_assignment_count[i]
        #print(self.clusters)

    def compute_clusters(self):
        self.cluster_allocation = {}
        iteration_count = 0
        while True:
            actual_clusters = self.assign_to_clusters()
            print("Cluster allocation:")
            print(actual_clusters)
            if self.dicts_are_equal(self.cluster_allocation, actual_clusters) or iteration_count > self.max_iterations:
                if iteration_count > self.max_iterations:
                    print("ALERT: clusters didn't converge - max iterations reached")
                self.cluster_allocation = actual_clusters
                return self.cluster_allocation
            else:
                self.cluster_allocation = actual_clusters
                self.compute_centroids()
            iteration_count = iteration_count + 1

    def calculate_example_centroid(self, example):
        if len(self.dimensions_index) > 1:
            return example[self.dimensions_index[0]], example[self.dimensions_index[1]]
        #pos = 0
        #for i in self.data_indexes:
        #    pos = pos + example[self.data_indexes[i]]
        #return pos, pos

    def scatter_plot_without_clsrs(self, labels):
        colors = iter([plt.cm.tab10(i) for i in range(20)])
        #positions = [self.calculate_example_centroid(self.data[i]) for i in range(0, len(self.data))]
        iter_pos = 0
        xAxisMotorola = []
        yAxisMotorola = []
        xAxisLG = []
        yAxisLG = []
        for label in labels:
            posX, posY = self.calculate_example_centroid(self.data[iter_pos])
            if 'Motorola' in label:
                xAxisMotorola.append(posX)
                yAxisMotorola.append(posY)
            else:
                xAxisLG.append(posX)
                yAxisLG.append(posY)
            iter_pos = iter_pos + 1
        fig, ax = plt.subplots()
        color_selected = next(colors)
        scatter = ax.scatter(xAxisMotorola, yAxisMotorola, color=color_selected)
        color_selected = next(colors)
        scatter = ax.scatter(xAxisLG, yAxisLG, color=color_selected)
        texts = []
        legend_handles = []
        if self.show_legends:
            for i, txt in enumerate(labels):
                patch = mpatches.Patch(color=color_selected, label=txt)
                legend_handles.append(patch)
                if self.show_text:
                    if self.adjust_text:
                        texts.append(plt.text(xAxis[i], yAxis[i], txt))
                    else:
                        ax.annotate(txt, (xAxis[i], yAxis[i]))
            if self.show_text:
                if self.adjust_text:
                    adjust_text(texts, precision=0.8, only_move={'objects': 'xy', 'points': 'xy', 'text': 'xy'}, arrowprops=dict(arrowstyle="->", color='r', lw=0.5))
            plt.legend(ncol=3, handles=legend_handles)
        plt.show()

    def scatter_plot_with_clusters(self, labels):
        colors = iter([plt.cm.tab20(i) for i in range(20)])
        positions = [self.calculate_example_centroid(self.data[i]) for i in range(0, len(self.data))]
        fig, ax = plt.subplots()
        cluster_colors = []
        for k in range(0, len(self.clusters)):
            xAxis = [positions[i][0] for i in range(0, len(positions)) if
                     self.cluster_allocation[i] == k]
            yAxis = [positions[i][1] for i in range(0, len(positions)) if
                     self.cluster_allocation[i] == k]
            selected_color = next(colors)
            ax.scatter(xAxis, yAxis, color=selected_color)
            cluster_colors.append(selected_color)
        xAxis2 = [positions[i][0] for i in range(0, len(positions))]
        yAxis2 = [positions[i][1] for i in range(0, len(positions))]
        texts = []
        legend_handles = []
        if self.show_legends:
            for i, txt in enumerate(labels):
                if self.show_text:
                    if self.adjust_text:
                        texts.append(plt.text(xAxis2[i], yAxis2[i], txt))
                    else:
                        ax.annotate(txt, (xAxis2[i], yAxis2[i]))
                attributed_cluster = self.cluster_allocation[i]
                cluster_color = cluster_colors[attributed_cluster]
                patch = mpatches.Patch(color=cluster_color, label=txt)
                legend_handles.append(patch)
            if self.show_text:
                if self.adjust_text:
                    adjust_text(texts, precision=0.8, only_move={'objects': 'xy', 'points': 'xy', 'text': 'xy'}, arrowprops=dict(arrowstyle="->", color='r', lw=0.5))
            plt.legend(ncol=3, handles=legend_handles)
        plt.show()

def show_locations_with_groups():
    connection_object = sqlite3.connect(
        "D:\\LGMotorola_consolidado.db")
    cursor = connection_object.cursor()
    sqlite_select_Query = """select id, std_time, Latitude, Longitude, Precision from vw_locations_motorola where cast(Precision as int)<21"""
    #sqlite_select_Query = """select id, std_time, Latitude, Longitude, Precision from vw_locations_lg where cast(Precision as int)<21"""
    cursor.execute(sqlite_select_Query)
    records = cursor.fetchall()
    data = {}
    pos = 0
    labels = []
    base_date_str = '2022-03-03 00:00:01'
    base_date = datetime.strptime(base_date_str, '%Y-%m-%d %H:%M:%S')
    for record in records:
        labels.append(record[0])
        item_id = record[0]
        dlat = Decimal(record[2])
        dlong = Decimal(record[3])
        if record[4] != '':
            precision = Decimal(1.0*int(record[4]))
        else:
            precision = Decimal(0.0)
        record_date_str = record[1]
        record_date = datetime.strptime(record_date_str, '%Y-%m-%d %H:%M:%S')
        diff = record_date - base_date
        minutes = diff.total_seconds() / 60
        data[pos] = [item_id, dlat, dlong, precision, Decimal(minutes*1.0)]
        pos = pos + 1
    #print(data)
    cursor.close()
    kmc = KMeansClustering(20, 100, data, [1, 2, 3, 4])
    kmc.adjust_text = False
    # kmc.set_clusters([0, 3, 6])
    kmc.create_clusters()
    kmc.scatter_plot_without_clsrs(labels)
    kmc.compute_clusters()
    cluster_allocations = kmc.cluster_allocation
    pos = 0
    print("Updating clusters in database")
    for item in labels:
        location_id = kmc.data[pos][0]
        cluster_id = cluster_allocations[pos]
        latitude = kmc.clusters[cluster_id][1]
        longitude = kmc.clusters[cluster_id][2]
        precision = kmc.clusters[cluster_id][3]
        minutes_from_base = kmc.clusters[cluster_id][4]
        base_date_str = '2022-03-03 00:00:01'
        base_date = datetime.strptime(base_date_str, '%Y-%m-%d %H:%M:%S')
        std_time = base_date + timedelta(minutes=int(minutes_from_base))
        std_time_str = std_time.strftime('%Y-%m-%d %H:%M:%S')
        sqlite = """delete from tb_clusters_1 where location_id = ?"""
        params = []
        params.append(location_id)
        cursor = connection_object.cursor()
        cursor.execute(sqlite, params)
        sqlite = """insert into tb_clusters_1(location_id, cluster_id, cluster_lattitude, cluster_longitude, cluster_precision, cluster_std_time) values (?, ?, ?, ?, ?, ?) """
        params = []
        params.append(str(location_id))
        params.append(str(cluster_id))
        params.append(str(latitude))
        params.append(str(longitude))
        params.append(str(precision))
        params.append(str(std_time_str))
        cursor = connection_object.cursor()
        cursor.execute(sqlite, params)
        connection_object.commit()
        pos = pos + 1
    kmc.scatter_plot_with_clusters(labels)


def test_examples():
    data = {0: [2, 10], 1: [2, 5], 2: [8, 4], 3: [5, 8], 4: [7, 5], 5: [6, 4], 6: [1, 2], 7: [4, 9]}
    kmc = KMeansClustering(3, 10, data, [0, 1])
    kmc.set_clusters([0, 3, 6])
    print(kmc.clusters)
    print(kmc.compute_clusters())
    kmc.scatter_plot_without_clsrs(["A", "B", "C", "D", "E", "F", "G", "H"])
    kmc.scatter_plot_with_clusters(["A", "B", "C", "D", "E", "F", "G", "H"])

def plot(lat, lng, api_key, zoom=10, map_type='roadmap'):
    gmap_options = GMapOptions(lat=lat, lng=lng,
                               map_type=map_type, zoom=zoom)
    p = gmap(api_key, gmap_options, title='Pays de Gex',
             width=800, height=600)
    show(p)
    return p

def plot(lat, lng, data, api_key, file_name="empty.html", title="no title", zoom=15, map_type='roadmap'):
    output_file(file_name)
    gmap_options = GMapOptions(lat=lat, lng=lng,
                               map_type=map_type, zoom=zoom)
    # the tools are defined below:
    p = gmap(api_key, gmap_options, title=title,
             width=1024, height=1024,
             tools=['hover', 'reset', 'wheel_zoom', 'pan'])
    center = p.square([lng], [lat], size=10, alpha=0.5, color='red')
    for data_item in data:
        if "LG" in data[data_item][0]:
            p.triangle(data[data_item][2], data[data_item][1], size=10, alpha=0.5, color='blue')
        else:
            p.circle(data[data_item][2], data[data_item][1], size=10, alpha=0.5, color='green')
    show(p)
    return p

def draw_locations_on_maps_per_day(type, day_str, zoom):
    connection_object = sqlite3.connect(
        "D:\\LGMotorola_consolidado.db")
    cursor = connection_object.cursor()
    if type == 'clusters':
        sqlite_select_Query = "select cluster_id, cluster_lattitude, cluster_longitude, cluster_precision, cluster_std_time from vw_clusters_agg where cluster_std_time between '"+day_str+" 00:00:01' and '"+day_str+" 23:59:59'"""
    if type == 'noclusters':
        sqlite_select_Query = "select Aparelho, Latitude, Longitude, Precision, std_time from locations_with_std_time where cast(Precision as int)<20 and std_time BETWEEN '" + day_str + " 00:00:01' and '" + day_str + " 23:59:59'"""

    #sqlite_select_Query = """select cluster_id, cluster_lattitude, cluster_longitude, cluster_precision, cluster_std_time from vw_clusters_agg """
    cursor.execute(sqlite_select_Query)
    records = cursor.fetchall()
    data = {}
    pos = 0
    avg_lat = Decimal(0)
    avg_long = Decimal(0)
    for record in records:
        cluster_id = record[0]
        cluster_lattitude = record[1]
        cluster_longitude = record[2]
        cluster_precision = record[3]
        cluster_std_time = record[4]
        dlat = Decimal(cluster_lattitude)
        dlong = Decimal(cluster_longitude)
        dprecision = Decimal(cluster_precision)
        data[pos] = [cluster_id, float(dlat), float(dlong), float(dprecision)]
        avg_lat = avg_lat + dlat
        avg_long = avg_long + dlong
        pos = pos + 1
    avg_lat = avg_lat/pos
    avg_long = avg_long/pos
    print("draw_locations_on_maps: Enter your Google Geolocation API Key")
    api_key = 'AIzaSyAupKro9Tf6y3jP3cs0TrLD85E2uu6TN9o'
    if True:
        for line in sys.stdin:
            api_key = line.rstrip()
            break
    print("Key: " + api_key + ":")
    plot(float(avg_lat), float(avg_long), data, api_key, type+'-'+day_str+".html", day_str, zoom=zoom)

if __name__ == '__main__':
    #show_locations_with_groups()
    #draw_locations_on_maps_per_day('clusters', '2022-03-03', 14)
    #draw_locations_on_maps_per_day('clusters', '2022-03-04', 13)
    draw_locations_on_maps_per_day('clusters', '2022-03-05', 22)
    #draw_locations_on_maps_per_day('clusters', '2022-03-06', 12)
    #draw_locations_on_maps_per_day('clusters', '2022-03-07', 14)
    #draw_locations_on_maps_per_day('clusters', '2022-03-08', 11)
    #draw_locations_on_maps_per_day('clusters', '2022-03-09', 11)
    name = input('What is your name1?\n')
    #draw_locations_on_maps_per_day('noclusters', '2022-03-03', 14)
    #draw_locations_on_maps_per_day('noclusters', '2022-03-04', 13)
    draw_locations_on_maps_per_day('noclusters', '2022-03-05', 22)
    #draw_locations_on_maps_per_day('noclusters', '2022-03-06', 12)
    #draw_locations_on_maps_per_day('noclusters', '2022-03-07', 14)
    #draw_locations_on_maps_per_day('noclusters', '2022-03-08', 11)
    #draw_locations_on_maps_per_day('noclusters', '2022-03-09', 11)
    name = input('What is your name2?\n')
