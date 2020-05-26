import matplotlib
import matplotlib.pyplot as plt
import numpy as np 
import math
import xml.etree.ElementTree as ET

index = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']

fake_data_dir = "./benchmark_result/fake"
file_src = ['wiki-Vote', 'email-Enron', 'email-EuAll', 'loc-gowalla_edges', 'com-youtube', 'wiki-Talk']

all_mean_result = []
all_max_result = []


for l in range(0, len(index)):
    get = [[] for i in range(0, 6)]
    k = 0
    for each in file_src:
        tree = ET.parse(fake_data_dir + index[l] + "/" + each + ".xml")
        root = tree.getroot()

        for rd in root.findall("redo"):
            get[k].append(int(rd.getchildren()[0].getchildren()[2].find("compare").text) * 0.16 / 60)
        k += 1

    # if l == 2:

    max_result = []
    mean_result = []
    for i in range(0, 6):
        mean_result.append(np.mean(get[i]))
        max_result.append(np.max(get[i]))

    all_mean_result.append(mean_result)
    all_max_result.append(max_result)

label = ['Vote', 'Enron', 'EuAll', 'Gowalla', 'Youtube', 'Talk']

# for i in range(0, len(index)):
#     plt.subplot(int(len(index) / 5), 5, i + 1)
#     plt.yscale('log')
#     plt.ylim(10**-2, 10**3)
#     plt.bar(label, all_mean_result[i], edgecolor = 'k', color='w')
#     plt.tick_params(labelsize=7)
#     plt.title("fake" + index[i])

#     m = 0
#     for a,b in zip(label, all_mean_result[i]):
#         plt.text(a, b + 0.05, "%d"%all_max_result[i][m], ha='center', fontsize=7)
#         m += 1

look_good_data = [
    all_mean_result[1][0],
    all_mean_result[8][1],
    all_mean_result[1][2],
    all_mean_result[6][3],
    all_mean_result[2][4],
    all_mean_result[2][5]
]

print look_good_data

plt.yscale('log')
plt.ylim(10**-2, 10**2)
plt.xlabel("Data sets", fontsize=14)
plt.ylabel("Query time (min)", fontsize=14)

plt.bar(range(1,7), look_good_data, width = 0.5, tick_label=label, edgecolor = 'k', color='w', hatch='///')

plt.show()
# plt.savefig('./img/dist.pdf', format='pdf')

# fake_src = [1, 8, 1, 6, 2, 2]

# for i in range(0,6):
#     req = []
#     tree = ET.parse(fake_data_dir + index[fake_src[i]] + "/" + file_src[i] + ".xml")
#     root = tree.getroot()
#     f = open("./data/fake/" + file_src[i] + ".data", "w")
#     for rd in root.findall("redo"):
#         src = rd.getchildren()[0].getchildren()[0].find("src").text
#         dest = rd.getchildren()[0].getchildren()[0].find("dest").text
#         req.append(src + " " + dest + "\n")
#     f.writelines(req)
#     f.close() 