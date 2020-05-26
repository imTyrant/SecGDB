#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <list>
#include <queue>
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

    inline Vertex():name("") {}
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

    // inline Edge(size_t w, Vertex *s, Vertex *d)
    // {
    //     this->weight = w;
    //     this->src = s;
    //     this->dest = d;
    // }

    inline Edge(size_t w, Vertex s, Vertex d) : weight(w), src(s), dest(d)
    {
        cout << "Edge initialization is done" << endl;
    }
    
    inline Edge():weight(0),src(""),dest("") {}
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

    inline bool find_edge(string& src, string& dest, Edge& edge)
    {
        if (this->adjacency_list.find(src) == this->adjacency_list.end())
        {
            return false;
        }
        for (Edge& e : this->adjacency_list.at(src))
        {
            if (e.dest.name == dest)
            {
                edge = e;
                return true;
            }
        }
        return false;
    }

    inline bool add_edge(string& src, string& dest, size_t weight)
    {
        if (this->vertices.find(src) == this->vertices.end() || this->vertices.find(dest) == this->vertices.end())
        {
            return false;
        }

        // if (this->adjacency_list.find(src) == this->adjacency_list.end())
        // {
        //     this->adjacency_list.at
        // }
        this->adjacency_list.at(src).push_back(Edge(weight, this->vertices.find(src)->second, this->vertices.find(dest)->second));
        return true;
    }

    inline void update_edge_add(string src, string dest, size_t weight)
    {
        Edge edge;
        if (!find_edge(src, dest, edge))
        {
            add_edge(src, dest, weight);
        }
        else
        {
            edge.weight += weight;
        }
    }
};




class Dinic
{
  private:
    Graph graph;
    unordered_map<string, size_t> level_graph;


  public:
    inline size_t dfs(const string &src, const string &dest, size_t capability)
    {
        size_t all_cap = 0;
        if (src == dest)
        {
            return capability;
        }

        size_t cur_level = this->level_graph.at(src);

        for (Edge& e: this->graph.adjacency_list.at(src))
        {
            if ((this-> level_graph.find(e.dest.name) != this->level_graph.end()) && (cur_level + 1) == this->level_graph.at(e.dest.name))
            {
                size_t tmp = this->dfs(e.dest.name, dest, ((capability - all_cap) < e.weight) ? (capability - all_cap): e.weight);
                this->graph.update_edge_add(e.dest.name, src, tmp);
                all_cap += tmp;
                e.weight -= tmp;
            }
        }

        return all_cap;
    }

    inline size_t augment_path(const string &s, const string &t)
    {
        return dfs(s, t, numeric_limits<size_t>::max());
    }

    inline bool find_vertex_level(const string &s, const string &t)
    {
        this->level_graph.clear();

        queue<string> q;

        q.push(s);
        this->level_graph.emplace(s, 0);

        while (!q.empty())
        {
            string cur_v = q.front();
            size_t cur_level = this->level_graph.at(cur_v);

            for (Edge& e : this->graph.adjacency_list.at(cur_v))
            {
                if ((this->level_graph.find(e.dest.name) == this->level_graph.end()) && e.weight > 0)
                {
                    q.push(e.dest.name);
                    this->level_graph.emplace(e.dest.name, cur_level + 1);
                }
            }
            q.pop();
        }

        return (this->level_graph.find(t) == this->level_graph.end()) ? false : true;
    }

    inline Dinic(Graph graph):graph(graph){}

    inline size_t find_max_flow(string s, string d)
    {
        size_t total = 0;
        while( find_vertex_level(s, d))
        {
            total += augment_path(s, d);
        }
        return total;
    }
};


int main(int argc, char *argv[])
{

    Graph graph(6);

    graph.build_graphic("../data/exh/email-Enron.data");

    Dinic di(graph);

    // unordered_map<int, list<int>> a;

    // a[1] = {1,2,3,4,5,6,7,9};
    // a[2] = {2};
    // a[3] = {3};
    // a[4] = {4};
    // a[5] = {5};
    // a[6] = {6};

    // for (auto& j : a.at(1))
    // {
    //     j++;
    // }


    cout << di.find_max_flow("4892", "36425") << "\n";

    return EXIT_SUCCESS;
}