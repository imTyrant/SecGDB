#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include "graph.hpp"

#include <boost/algorithm/string.hpp>

using namespace std;

template <class T>
Graph<T>::Graph() : vertices(), adjacency_list()
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
void build_graph(Graph<size_t> &graph, const string &file_path)
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

        size_t weight = (size_t)std::stoi(strs[2]);

        graph.add_edge(strs[0], strs[1], weight);

    }

    in_file.close();
}

/**
 * Find wether or not an edge is existed between the specified verteices.
 * If yes, reture the iterator of the edge, 
 * else return the end of the list.
*/
template <class T>
typename vector<Edge<T>>::iterator Graph<T>::find_edge(const Vertex &src, const Vertex &dest)
{
    vector<Edge<T>> &tmp = this->adjacency_list[src];
    for (auto it = tmp.begin(); it != tmp.end(); it++)
    {
        if (it->dest == dest)
        {
            return it;
        }
    }
    return tmp.end();
}

/**
 * Add an new edge between src and dest. If there is an exisiting edge,
 * modify the weigt of the edge.
*/
template <class T>
void Graph<T>::add_edge(string &src, string &dest, T &weight)
{
    if (this->vertices.find(src) == this->vertices.end())
    {
        Vertex v_src{src, 0, 0};
        this->vertices[src] = v_src;
        this->num_vertices++;
        this->adjacency_list[v_src] = vector<Edge<T>>();
    }

    if (this->vertices.find(dest) == this->vertices.end())
    {
        Vertex v_dest{dest, 0, 0};
        this->vertices[dest] = v_dest;
        this->num_vertices++;
        this->adjacency_list[v_dest] = vector<Edge<T>>();
    }

    auto tmp = this->find_edge(this->vertices[src], this->vertices[dest]);
    if (tmp != this->adjacency_list[this->vertices[src]].end())
    {
        tmp->weight = weight;
    }
    else
    {
        this->adjacency_list.at(this->vertices[src]).emplace_back(Edge<T>{this->vertices[src], this->vertices[dest], weight});
        this->vertices[src].out_degree++;
        this->vertices[dest].in_degree++;
        this->num_edges++;
    }
}

/**
 * Change weight of the edge specified.
 * Assume the edge is existed.
*/
template <class T>
void Graph<T>::modify_edge(string &src, string &dest, T &weight)
{
    auto edge = find_edge(this->vertices.at(src), this->vertices.at(dest));
    edge->weight = weight;
}

template <class T>
void Graph<T>::clear()
{
    this->adjacency_list.clear();
    this->vertices.clear();
    this->num_edges = this->num_vertices = 0;
}

template class Graph<size_t>;
#include <gmpxx.h>
template class Graph<mpz_class>;