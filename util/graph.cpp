#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include "graph.hpp"

#include <boost/algorithm/string.hpp>

using namespace std;

Graph::Graph() : vertices(), adjacency_list()
{
    this->num_edges = this->num_vertices = 0;
}

/**
 * Read graph from file.
 * The format of graph should be:
 * Vertex Vertex Weight
 * the frist Vertex denote the source and the second is the destination.
 * Weight should be a interger more than 0.
 */
void Graph::build_graph(const string &file_path)
{
    ifstream in_file(file_path, std::ifstream::in);
    string line;

    
    if (in_file.fail()) {
        std::cout << "Read graph file failed!\n";
    }

    while (std::getline(in_file, line))
    {
        vector<string> strs;

        boost::split(strs, line, boost::is_any_of(" "));

        if (this->vertices.find(strs[0]) == this->vertices.end())
        {
            this->vertices.emplace(strs[0], Vertex{strs[0], 0, 0});
            this->num_vertices++;
            this->adjacency_list.emplace(this->vertices[strs[0]], list<Edge>());
        }

        Vertex &src = this->vertices[strs[0]];
        src.out_degree++;

        if (this->vertices.find(strs[1]) == this->vertices.end())
        {
            this->vertices.emplace(strs[1], Vertex{strs[1], 0, 0});
            this->num_vertices++;
        }

        Vertex &dest = this->vertices[strs[1]];
        dest.in_degree++;

        this->adjacency_list[src].emplace_back(Edge{src, dest, (size_t)std::stoi(strs[2])});

        this->num_edges++;
    }

    in_file.close();
}