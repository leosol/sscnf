import matplotlib.patches as mpatches
import numpy as np
from adjustText import adjust_text
from decimal import *
import random
import matplotlib.pyplot as plt
from matplotlib.pyplot import cm
import sqlite3
import adjustText


class KMeansClustering:
    def __init__(self, k, max_iterations, data, data_indexes):
        self.k = k
        self.max_iterations = max_iterations
        self.data = data
        self.clusters = {}
        self.cluster_allocation = {}
        self.data_indexes = data_indexes
        self.adjust_text = False
        self.show_text = False

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
        for i in self.data_indexes:
            distance = distance + (item[i] - clsr[i]) ** 2
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
            for j in self.data_indexes:
                self.clusters[i][j] = Decimal(0)

        for i in range(0, len(self.data)):
            data_item = self.data[i]
            data_cluster_index = self.cluster_allocation[i]
            cluster = self.clusters[data_cluster_index]
            clusters_assignment_count[data_cluster_index] = clusters_assignment_count[data_cluster_index] + 1
            for j in self.data_indexes:
                cluster[j] = cluster[j] + Decimal(data_item[j])

        for i in range(0, len(self.clusters)):
            for j in self.data_indexes:
                if clusters_assignment_count[i]>0:
                    self.clusters[i][j] = self.clusters[i][j] / clusters_assignment_count[i]
        print(self.clusters)

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
        if len(self.data_indexes) == 2:
            return example[self.data_indexes[0]], example[self.data_indexes[1]]
        pos = 0
        for i in self.data_indexes:
            pos = pos + example[self.data_indexes[i]]
        return pos, pos

    def scatter_plot_without_clsrs(self, labels):
        color = iter(cm.rainbow(np.linspace(0, 1, 2)))
        next(color)
        positions = [self.calculate_example_centroid(self.data[i]) for i in range(0, len(self.data))]
        xAxis = [positions[i][0] for i in range(0, len(positions))]
        yAxis = [positions[i][1] for i in range(0, len(positions))]
        fig, ax = plt.subplots()
        color_selected = next(color)
        scatter = ax.scatter(xAxis, yAxis, color=color_selected)
        texts = []
        legend_handles = []
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
        #plt.legend(ncol=3, handles=legend_handles)
        plt.show()

    def scatter_plot_with_clusters(self, labels):
        positions = [self.calculate_example_centroid(self.data[i]) for i in range(0, len(self.data))]
        color = iter(cm.rainbow(np.linspace(0, 1, 200)))
        next(color)
        fig, ax = plt.subplots()
        cluster_colors = []
        for k in range(0, len(self.clusters)):
            xAxis = [positions[i][0] for i in range(0, len(positions)) if
                     self.cluster_allocation[i] == k]
            yAxis = [positions[i][1] for i in range(0, len(positions)) if
                     self.cluster_allocation[i] == k]
            selected_color = next(color)
            ax.scatter(xAxis, yAxis, color=selected_color)
            cluster_colors.append(selected_color)
        xAxis2 = [positions[i][0] for i in range(0, len(positions))]
        yAxis2 = [positions[i][1] for i in range(0, len(positions))]
        texts = []
        legend_handles = []
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
        #plt.legend(ncol=3, handles=legend_handles)
        plt.show()



def vw_expected_time_vs_permissions():
    connection_object = sqlite3.connect(
        "E:\\davi_locations.db")
    cursor = connection_object.cursor()
    sqlite_select_Query = """select dispositivo||' - '||hora, cast(Latitude as decimal), cast(Longitude as decimal) from davi_locations_csv"""
    cursor.execute(sqlite_select_Query)
    records = cursor.fetchall()
    data = {}
    pos = 0
    labels = []
    for record in records:
        labels.append(record[0].replace("com.", "").replace("google.android.", ""))
        data[pos] = [Decimal(record[2]), Decimal(record[1])]
        pos = pos + 1
    print(data)
    cursor.close()
    kmc = KMeansClustering(20, 100, data, [0, 1])
    kmc.adjust_text = False
    # kmc.set_clusters([0, 3, 6])
    kmc.create_clusters()
    kmc.scatter_plot_without_clsrs(labels)
    print(kmc.compute_clusters())
    kmc.scatter_plot_with_clusters(labels)


def test_examples():
    data = {0: [2, 10], 1: [2, 5], 2: [8, 4], 3: [5, 8], 4: [7, 5], 5: [6, 4], 6: [1, 2], 7: [4, 9]}
    kmc = KMeansClustering(3, 10, data, [0, 1])
    kmc.set_clusters([0, 3, 6])
    print(kmc.clusters)
    print(kmc.compute_clusters())
    kmc.scatter_plot_without_clsrs(["A", "B", "C", "D", "E", "F", "G", "H"])
    kmc.scatter_plot_with_clusters(["A", "B", "C", "D", "E", "F", "G", "H"])


if __name__ == '__main__':
    vw_expected_time_vs_permissions()
    name = input('What is your name?\n')
