import xml.etree.ElementTree as ET
import random

dic = "./data/exh/"

file_src = ['wiki-Vote.data', 'email-Enron.data', 'email-EuAll.data', 'loc-gowalla_edges.data', 'com-youtube.data', 'wiki-Talk.data']

for each in file_src:
    print dic + each + ".fake.xml"
    tree = ET.parse(dic + each + ".fake.xml")
    root = tree.getroot()

    f = open(dic + "fake_data/" + each.split(".")[0] + ".fake", "w")
    k = 0
    for child in root:
        data = []
        for element in child:
            data.append(element.text)

        chosen = []
        for i in range(0, 30 - k * 13):
            random.seed()
            index = random.randint(0, len(data) - 1)
            while index in chosen:
                index = random.randint(0, len(data) - 1)
            chosen.append(index)
        k += 1

        out = []
        for c in chosen:
            dmd = data[c].split("->")
            out.append(dmd[0] + " " + dmd[-1] + "\n")
        f.writelines(out)
    f.close()