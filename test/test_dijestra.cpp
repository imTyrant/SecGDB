#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <list>
#include <boost/algorithm/string.hpp>

using namespace std;


class Vertex
{
  public:
    string name;
    size_t inDegree;
    size_t outDegree;

    inline Vertex(string name) : name(name)
    {
        inDegree = 0;
        outDegree = 0;
    }
};
Vertex resolve_vertex_phrase(string phrase)
{
    vector<string> strs;

    boost::split(strs, phrase, boost::is_any_of(" "));
    return Vertex(strs[1]);
}


class Edge
{
  public:
    size_t weight;
    Vertex src;
    Vertex dest;

    // inline Edge(int w, Vertex *s, Vertex *d)
    // {
    //     this->weight = w;
    //     this->src = s;
    //     this->dest = d;
    // }

    inline Edge(int w, Vertex s, Vertex d) : weight(w), src(s), dest(d)
    {
        cout << "Edge initialization is done" << endl;
    }
};

Edge resolve_edge_phrase(string phrase, unordered_map<string, Vertex> &vertices)
{
    vector<string> strs;

    boost::split(strs, phrase, boost::is_any_of(" "));

    return Edge(std::stoi(strs[3]), vertices.find(strs[1])->second, vertices.find(strs[2])->second);
}


class Graph
{
  private:
    size_t vertex_num;
    size_t edge_num;

  public:
    unordered_map<string, Vertex> vertices;
    unordered_map<string, list<Edge>> adjacency_list;

    inline Graph(int amount) : adjacency_list(), vertices()
    {
        this->vertex_num = amount;
        this->edge_num = 0;
    }

    inline int get_num_of_verteces()
    {
        return this->vertex_num;
    }

    inline void build_graphic(string name)
    {
        ifstream infile(name);
        string line;

        for (int i = 0; i < this->vertex_num; i++)
        {

            std::getline(infile, line);
            Vertex v = resolve_vertex_phrase(line);
            this->vertices.emplace(v.name, v);
            this->adjacency_list.emplace(v.name, list<Edge>());
        }

        while (std::getline(infile, line))
        {
            Edge e = resolve_edge_phrase(line, this->vertices);
            this->adjacency_list.find(e.src.name)->second.push_back(e);
        }

        infile.close();
    }
};


class Dinic
{
  private:
  public:
};

string find_nearest_neighbor(const unordered_map<string, int>& distance)
{
    int min = numeric_limits<int>::max();
    string rtn;

    for (auto it = distance.begin(); it != distance.end(); it++)
    {
        if (it->second < min)
        {
            rtn = it->first;
            min = it->second;
        }  
    }

    return rtn;
}

class Dijkestra
{
  private:
    Graph graph;
    unordered_map<string, int> distance;
    // unordered_map<string, string> previous;

  public:
    inline Dijkestra(Graph graph) : graph(graph), distance(){}

    inline int find_shortest_parth(string s, string t)
    {
        for (auto it = this->graph.vertices.begin(); it != this->graph.vertices.end(); it++)
        {
            this->distance.emplace(it->first, numeric_limits<int>::max());
        }

        this->distance.at(s) = 0;

        while(!this->distance.empty())
        {
            string min = find_nearest_neighbor(this->distance);
            int curLength = this->distance.at(min);

            if (min == t)
            {
                return curLength;
            }

            this->distance.erase(min);

            for(Edge e : this->graph.adjacency_list.at(min))
            {
                int alt = curLength + e.weight;
                // Use find for out of range error.
                auto neighbor = this->distance.find(e.dest.name);
                if (neighbor != this->distance.end())
                {

                    if (alt < neighbor->second)
                    {
                        neighbor->second = alt;
                    }
                }
            }
        }

        return numeric_limits<int>::max();
    }
};

int main(int argc, char *argv[])
{

    Graph graph(6);

    graph.build_graphic("test.txt");

    Dijkestra dij(graph);

    cout << dij.find_shortest_parth("A", "F") << endl;

    return EXIT_SUCCESS;
}